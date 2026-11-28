"""HTTP, MCP and Suzaku contract tests with a disposable, real CloudTrail DuckDB database."""
from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import gc
import base64
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
import time
import unittest
from unittest.mock import patch
import warnings
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import anyio
from mcp import Client, StdioServerParameters

import duckdb

from kamotrace.importer import build
from kamotrace.server import Handler
from kamotrace.mcp_server import http_transport
from case_fixtures import case_for, open_fixture as Store, enrich, import_timeline


def inventory_fixture(folder):
    """Synthetic current configuration, including an intentionally ambiguous private address/name."""
    resources = []
    for identifier, region, status, addresses in [
        ("i-example", "ap-southeast-3", "Restricted", ["10.0.1.5", "1.1.1.1"]),
        ("i-other", "us-east-1", "Blocked", ["10.0.1.5"]),
        ("i-alpha", "ap-southeast-3", "Blocked", ["10.0.1.9"]),
    ]:
        resources.append({"id": identifier, "name": "application" if identifier != "i-alpha" else "worker <synthetic>",
            "kind": "EC2", "region": region, "vpc_id": "vpc-test", "subnet_ids": ["subnet-test"],
            "state": "running", "addresses": addresses, "security_groups": ["sg-test"], "details": {"instance_type": "t3.small"},
            "status": status, "summary": "Synthetic configuration assessment, not a connection test", "paths": [],
            "direct_status": status, "indirect_status": "None", "via_load_balancers": [],
            "iam_roles": ["application-role"], "iam_role_arns": ["arn:aws:iam::123:role/application-role"],
            "iam_role_status": "Resolved", "iam_instance_profile": "arn:aws:iam::123:instance-profile/application"})
    resources.append({"id": "lb-synthetic", "name": "application-gateway", "kind": "Load balancer",
        "region": "ap-southeast-3", "vpc_id": "vpc-test", "subnet_ids": ["subnet-test"],
        "state": "active", "addresses": ["gateway.synthetic.invalid"], "security_groups": ["sg-test"],
        "status": "Restricted", "direct_status": "Restricted", "indirect_status": "None", "via_load_balancers": [],
        "summary": "Synthetic restricted frontend; configuration is not a connection test", "paths": [],
        "iam_roles": [], "iam_role_arns": [], "iam_role_status": "Not applicable", "details": {}})
    resources[0].update(indirect_status="Configured", via_load_balancers=["application-gateway"])
    route = {"id": "route-synthetic", "region": "ap-southeast-3", "load_balancer_id": "lb-synthetic",
        "load_balancer_name": "application-gateway", "scheme": "internet-facing", "listener_id": "listener-synthetic",
        "listener_protocol": "HTTPS", "listener_port": 443, "rule_id": "rule-synthetic", "priority": "default",
        "conditions": [], "actions": [{"Type": "forward", "TargetGroupArn": "target-group-synthetic"}],
        "target_group_id": "target-group-synthetic", "target_group_name": "application-backends", "target_type": "instance",
        "target_id": "i-example", "target_resource_id": "i-example", "target_resource_region": "ap-southeast-3",
        "target_name": "application", "target_port": 8080, "health": "healthy", "weight": 1,
        "frontend_status": "Restricted", "network_status": "Restricted", "status": "Configured", "public_entry": True,
        "reason": "Synthetic forwarding configuration; not successful access", "network_evidence": ["Synthetic restricted backend path"]}
    report = {"metadata": {"account": "123", "started_at_utc": "2026-10-29T15:00:00Z",
        "completed_at_utc": "2026-10-29T15:01:00Z", "regions": ["ap-southeast-3", "us-east-1"],
        "limitations": ["Current configuration snapshot, not historical incident-time state.", "No active probes are performed."]},
        "resources": resources, "vpcs": [{"id": "vpc-test", "region": region, "name": "Synthetic VPC",
                                          "cidr": "10.0.0.0/16, 2001:db8:1234::/56"}
            for region in ("ap-southeast-3", "us-east-1")],
        "subnets": [{"id": "subnet-range", "name": "Synthetic subnet", "region": "ap-southeast-3",
                     "vpc_id": "vpc-test", "availability_zone": "ap-southeast-3a",
                     "cidr": "10.0.1.128/25, 2001:db8:1234:80::/64"}],
        "security_groups": [{"id": "sg-test", "name": "Application ingress", "region": "ap-southeast-3", "vpc_id": "vpc-test",
                             "ingress": [], "egress": [], "resources": ["i-example", "i-alpha"]}],
        "relationships": [], "forwarding_paths": [route], "listener_actions": [],
        "errors": [{"region": "us-east-1", "operation": "describe_db_instances", "error": "AccessDenied (synthetic)"}],
        "counts": {"Restricted": 2, "Blocked": 2}}
    report["iam"] = {
        "started_at_utc": "2026-10-29T15:01:00Z", "completed_at_utc": "2026-10-29T15:02:00Z", "errors": [],
        "users": [{"UserName": "analyst", "UserId": "AIDANALYST", "Arn": "arn:aws:iam::123:user/team/analyst",
                   "GroupList": ["investigators"], "CreateDate": "2025-01-01T00:00:00Z",
                   "activity": {"console_status": "collected", "password_last_used": "2026-10-27T12:30:00Z", "access_keys_status": "collected", "access_keys": [
                       {"AccessKeyId": "AKIASYNTHETICKEY1", "Status": "Active", "CreateDate": "2025-03-04T00:00:00Z", "last_used_status": "collected",
                        "last_used": {"LastUsedDate": "2026-10-28T04:10:00Z", "ServiceName": "s3", "Region": "ap-southeast-1"}},
                       {"AccessKeyId": "AKIASYNTHETICKEY2", "Status": "Inactive", "CreateDate": "2025-03-05T00:00:00Z", "last_used_status": "collected", "last_used": {}}]},
                   "UserPolicyList": [{"PolicyName": "inline-user", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}]}}]}],
        "roles": [{"RoleName": "auditor", "RoleId": "AROAUDITOR", "Arn": "arn:aws:iam::123:role/team/auditor",
                   "RoleLastUsed": {"LastUsedDate": "2026-10-28T09:15:00Z", "Region": "ap-southeast-1"},
                   "AssumeRolePolicyDocument": {"Statement": [
                       {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ec2.amazonaws.com"}},
                       {"Sid": "Partner", "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ["*", "arn:aws:iam::456:root"]},
                        "Condition": {"StringEquals": {"sts:ExternalId": "synthetic"}}},
                       {"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": "*"}]},
                   "RolePolicyList": [{"PolicyName": "inline-role", "PolicyDocument": {"Statement": []}}],
                   "AttachedManagedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
                   "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::123:policy/Boundary"}}],
        "groups": [{"GroupName": "investigators", "GroupId": "AGPINVESTIGATORS", "Arn": "arn:aws:iam::123:group/team/investigators",
                    "GroupPolicyList": [{"PolicyName": "inline-group", "PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}}],
                    "AttachedManagedPolicies": [{"PolicyName": "CaseRead", "PolicyArn": "arn:aws:iam::123:policy/CaseRead"}]}],
        "policies": [{"PolicyName": name, "Arn": f"arn:aws:iam::123:policy/{name}", "DefaultVersionId": "v2",
                      "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": False, "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
                                            {"VersionId": "v2", "IsDefaultVersion": True, "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::synthetic/*"}]}}]}
                     for name in ("CaseRead", "Boundary")],
        "aws_managed_policies": [{"PolicyName": "ReadOnlyAccess", "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "DefaultVersionId": "v99"}]}
    folder.mkdir()
    (folder / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return report


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
                "InstanceName": "ssm-worker", "Status": status, "CommandPlugins": [{"Name": "shell", "Output": "combined fallback", "Status": status}]
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
        cls.inventory_export = root / "inventory"
        cls.inventory_report = inventory_fixture(cls.inventory_export)
        cls.store = Store(cls.database, ssm_export=cls.ssm_export, inventory_export=cls.inventory_export)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=cls.store))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.transports = ExitStack()
        cls.server.mcp_request = cls.transports.enter_context(http_transport(cls.url))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.transports.close()
        if cls.store.exports is not None:
            cls.store.exports.close()
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

    def test_ui_cancellation_running_queued_and_late_requests(self):
        def start():
            status, response = self.call("/api/operations", {"action": "start"})
            self.assertEqual(status, 200)
            return response["token"]

        def cancel(token):
            return self.call("/api/operations", {"action": "cancel", "token": token})

        def events(token):
            return self.call("/api/events", {}, {"X-KamoTrace-Operation": token})

        original = self.store.rows
        def expensive(sql, params=None, *, operation="rows"):
            if operation == "events.page":
                # Real, bounded-memory DuckDB work, not a delayed/mocked response.
                original("SELECT sum(sin(i)) FROM range(10000000000) t(i)")
            return original(sql, params, operation=operation)

        def wait_running():
            until = time.monotonic() + 5
            while time.monotonic() < until:
                if self.store.connection.query_progress() >= 0:
                    return
                time.sleep(0.01)
            self.fail("DuckDB query did not start")

        with self.store.lock:
            self.store.connection.execute("SET enable_progress_bar=true; SET enable_progress_bar_print=false; SET progress_bar_time=1")
        try:
            token = start()
            self.assertTrue(cancel(token)[1]["cancelled"])
            self.assertEqual(events(token)[1]["cancelled"], True)  # Cancel before dispatch.
            self.assertEqual(events(token)[0], 400)  # Capabilities are single-use.
            with ThreadPoolExecutor(max_workers=2) as pool, patch.object(self.store, "rows", expensive):
                active = start()
                future = pool.submit(events, active)
                try:
                    wait_running()
                    self.assertFalse(cancel("unknown-capability")[1]["cancelled"])
                    self.assertFalse(cancel(token)[1]["cancelled"])  # Late cancel cannot hit new work.
                    queued = start()
                    waiting = pool.submit(events, queued)
                    until = time.monotonic() + 2
                    while time.monotonic() < until:
                        with self.store.operation_lock:
                            claimed = self.store.operations[queued]["claimed"]
                        if claimed:
                            break
                        time.sleep(0.01)
                    self.assertTrue(claimed, "Second request never joined the queue")
                    self.assertTrue(cancel(queued)[1]["cancelled"])
                    self.assertEqual(waiting.result(timeout=2)[1]["cancelled"], True)
                    self.assertFalse(future.done())  # Cancelling queued work did not interrupt its neighbor.
                    before = time.monotonic()
                    self.assertTrue(cancel(active)[1]["cancelled"])
                    status, result = future.result(timeout=3)
                    self.assertEqual(status, 409, result)
                    self.assertTrue(result["cancelled"])
                    self.assertLess(time.monotonic() - before, 3)
                finally:
                    cancel(active)
            entered, release = threading.Event(), threading.Event()
            def between_check_and_execute(sql, params=None, *, operation="rows"):
                if operation == "events.page":
                    entered.set()
                    if not release.wait(3):
                        raise ValueError("Test did not release statement startup")
                    # Deliberately enter execute AFTER cancel: DuckDB ignores a prior interrupt.
                    self.store.connection.execute("SELECT sum(sin(i)) FROM range(10000000000) t(i)").fetchall()
                return original(sql, params, operation=operation)
            with ThreadPoolExecutor(max_workers=1) as pool, patch.object(self.store, "rows", between_check_and_execute):
                active = start()
                future = pool.submit(events, active)
                try:
                    self.assertTrue(entered.wait(3))
                    self.assertTrue(cancel(active)[1]["cancelled"])
                    release.set()
                    self.assertTrue(future.result(timeout=3)[1]["cancelled"])
                finally:
                    release.set()
                    cancel(active)
            # A real query, histogram, and review read still work after interruption.
            self.assertEqual(events(start())[1]["last_row"], 5)
            self.assertEqual(self.call("/api/histogram", {})[1]["total"], 5)
            self.assertEqual(self.call("/api/reviews")[0], 200)
            self.assertFalse(cancel(active)[1]["cancelled"])
        finally:
            with self.store.lock:
                self.store.connection.execute("SET enable_progress_bar=false; SET progress_bar_time=2000")

    def test_pipeline_boolean_null_search_and_external_scopes(self):
        def check(text, expected, **external):
            body = {"pipeline": text, "pipeline_version": 1, **external}
            status, result = self.call("/api/events", body)
            self.assertEqual(status, 200, result)
            self.assertEqual({r["event_id"] for r in result["data"]}, {f"event-{i}" for i in expected})
            self.assertEqual(result["last_row"], len(expected))
            self.assertEqual(self.call("/api/histogram", body)[1]["total"], len(expected))
            self.assertEqual(self.call("/api/column-values", {**body, "field": "event_name"})[1]["total"], len(expected))
            return result
        check('event_id = "event-0" OR event_id = "event-1" AND source_ip = "8.8.8.8"', [0])
        check('(event_id = "event-0" OR event_id = "event-1") AND source_ip = "8.8.8.8"', [])
        check('event_name = "SendCommand" OR event_name = "StartSession" | country = "Indonesia" OR event_id = "event-1"', [1, 2])
        check('NOT user_agent contains "powershell"', [0, 2, 3, 4])
        check('user_agent != "powershell"', [0, 1, 2, 3, 4])
        check('user_agent is missing', [0, 2, 3, 4])
        check('user_agent is empty', [0, 2, 3, 4])
        check('user_agent is not empty AND user_agent is not missing', [1])
        check('user_agent = ""', [])
        check('user_agent contains ""', [1])
        check('NOT user_agent in ("absent")', [0, 1, 2, 3, 4])
        check('search ""', [0, 1, 2, 3, 4])
        check('NOT search ""', [])
        for value in ['"& C:', r'C:\\Temp\\a.ps1', '9007199254740993']:
            check('search ' + json.dumps(value), [0, 1, 2, 3, 4] if value.isdigit() else [1])
        check('search "left|right" OR search "雲"', [])
        injected = check('event_name = ' + json.dumps("' OR TRUE --"), [])
        self.assertNotIn("' OR TRUE --", injected["sql"])
        self.assertIn("' OR TRUE --", injected["params"])
        check('search "" OR event_id = "event-4"', [1, 2, 3],
              start="2026-10-24T17:00:00Z", end="2026-10-25T17:00:00Z", timezone="Asia/Jakarta")
        check('event_name = "SendCommand" OR search "StartSession"', [2],
              filters=[{"field": "country", "op": "eq", "value": "Indonesia"}])
        check('', [1], search="StartSession")

    def test_pipeline_validation_spans_registry_and_limits(self):
        def validate(text, version=1):
            return self.call("/api/pipeline", {"pipeline": text, "pipeline_version": version})
        text = ' tag in ("a|b", "c") \n| NOT lead = "x" OR region = "r" | (tag = "d") '
        status, result = validate(text)
        self.assertEqual(status, 200, result)
        self.assertEqual([text[s["start"]:s["end"]] for s in result["stages"]],
                         ['tag in ("a|b", "c")', 'NOT lead = "x" OR region = "r"', '(tag = "d")'])
        self.assertEqual(result["stages"][0]["values"], ["a|b", "c"])
        self.assertEqual(result["stages"][0]["field"], "tag")
        self.assertEqual(set(result["stages"][1]["fields"]), {"lead", "region"})
        self.assertEqual([s["field"] for s in result["stages"]][1:], [None, None])
        for text, expected in [('  ', ''), ('SeArCh "a|b"', 'a|b'), ('NOT search "a"', None), ('(search "a")', None)]:
            self.assertEqual(validate(text)[1]["search"], expected)
        fields = self.call("/api/meta")[1]["pipeline_fields"]
        self.assertNotIn("time_local", fields)
        self.assertEqual(fields["event_name"]["label"], "Operation")
        self.assertEqual(fields["event_source"]["label"], "AWS service")
        self.assertEqual(fields["tag"]["operators"], ["=", "!=", "in"])
        good = ['NOT ' * 20 + 'search ""', '(' * 20 + 'tag in ("a")' + ')' * 20,
                ' | '.join(['search ""'] * 20), ' AND '.join(['search ""'] * 100),
                'tag in (' + ','.join(['"a"'] * 100) + ')', 'search "' + 'a' * 2000 + '"',
                'search "\\ud83d\\ude00"', 'region is not missing', 'search "\\n\\t\\\\\\\""']
        for text in good:
            self.assertEqual(validate(text)[0], 200, text[:100])
        bad = ['| search ""', 'search "" |', 'search "" || search ""', 'search "" search ""',
               'time_local = "today"', 'unknown = "x"', 'tag contains "x"', 'lead is missing',
               'region = bare', "region = 'x'", 'search "\\q"', 'search "\\ud800"', 'search "x\ny"',
               'searcher "x"', 'region = "x" ORDER BY id', '(search "" | search "")',
               'NOT ' * 21 + 'search ""', '(' * 21 + 'search ""' + ')' * 21,
               ' | '.join(['search ""'] * 21), ' AND '.join(['search ""'] * 101),
               'tag in (' + ','.join(['"a"'] * 101) + ')', 'search "' + 'a' * 2001 + '"', ' ' * 8001]
        for text in bad:
            for endpoint in ("/api/pipeline", "/api/events", "/api/histogram", "/api/column-values"):
                status, error = self.call(endpoint, {"pipeline": text, "pipeline_version": 1, "field": "region"})
                self.assertEqual(status, 400, (endpoint, text[:100], error))
                self.assertTrue({"line", "column", "start", "end"} <= error.keys(), error)
        for version in (None, True, "1", 2):
            self.assertEqual(validate('', version)[0], 400)
        error = validate('search "" |\nunknown = "x"')[1]
        self.assertEqual((error["line"], error["column"]), (2, 1))
        text = 'search "😀" | tag = "x"'
        stages = validate(text)[1]["stages"]
        encoded = text.encode("utf-16-le")
        self.assertEqual([encoded[s["start"] * 2:s["end"] * 2].decode("utf-16-le") for s in stages],
                         ['search "😀"', 'tag = "x"'])
        error = validate('search "😀" | unknown = "x"')[1]
        self.assertEqual((error["start"], error["end"], error["column"]), (14, 21, 15))
        error = validate('search "😀" |')[1]
        self.assertEqual((error["start"], error["end"]), (13, 13))

    def test_pipeline_tag_memberships_and_legacy_intersection(self):
        rows = self.call("/api/events", {})[1]["data"]
        hashes = {row["event_id"]: row["record_sha256"] for row in rows}
        for slug, ids in [("pipeline-a", [0, 1]), ("pipeline-b", [1, 2])]:
            self.assertEqual(self.call("/api/reviews", {"action": "tag", "slug": slug,
                "color": "#123456", "hashes": [hashes[f"event-{i}"] for i in ids]})[0], 200)
        try:
            for text, ids, external in [
                ('tag in ("pipeline-a", "pipeline-b")', [0, 1, 2], {}),
                ('tag = "pipeline-a" AND tag = "pipeline-b"', [1], {}),
                ('tag != "pipeline-a"', [2, 3, 4], {}),
                ('NOT tag = "not-present"', [0, 1, 2, 3, 4], {}),
                ('tag in ("pipeline-a", "pipeline-b")', [1], {"tags": ["pipeline-a", "pipeline-b"]}),
                ('lead in ("absent") OR tag = "pipeline-a"', [0, 1], {})]:
                body = {"pipeline": text, "pipeline_version": 1, **external}
                status, result = self.call("/api/events", body)
                self.assertEqual(status, 200, result)
                self.assertEqual({r["event_id"] for r in result["data"]}, {f"event-{i}" for i in ids})
                self.assertEqual(self.call("/api/histogram", body)[1]["total"], len(ids))
        finally:
            for slug in ("pipeline-a", "pipeline-b"):
                self.call("/api/reviews", {"action": "untag", "slug": slug, "hashes": list(hashes.values())})

    def test_pipeline_empty_values_and_summaries_beyond_first_page(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            events = [{"eventID": f"page-{i}", "eventTime": "2026-10-25T01:02:03Z",
                       "eventName": "Synthetic", "awsRegion": "us-east-1",
                       **({"userAgent": ""} if i < 10 else {"userAgent": " "} if i < 20 else {})}
                      for i in range(35)]
            source = root / "events.json"
            source.write_text(json.dumps({"Records": events}), encoding="utf-8")
            build(source, root / "events.duckdb")
            store = Store(root / "events.duckdb")
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def post(path, **body):
                request = Request(f"http://127.0.0.1:{server.server_port}" + path, data=json.dumps(body).encode(),
                                  headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=15) as response:
                    return json.load(response)
            try:
                for text, count in [('user_agent = ""', 10), ('user_agent is missing', 15),
                                    ('user_agent is empty', 25), ('NOT user_agent contains ""', 15),
                                    ('user_agent contains ""', 20), ('user_agent = " "', 10),
                                    ('user_agent != ""', 25)]:
                    result = post('/api/events', pipeline=text, pipeline_version=1)
                    self.assertEqual(result['last_row'], count, text)
                body = {"pipeline": 'user_agent is empty OR user_agent = " "', "pipeline_version": 1, "size": 25}
                first = post('/api/events', **body)
                second = post('/api/events', **body, page=2)
                self.assertEqual((len(first['data']), len(second['data']), first['last_row']), (25, 10, 35))
                self.assertEqual(len({row['id'] for row in first['data'] + second['data']}), 35)
                self.assertEqual(post('/api/histogram', **body)['total'], 35)
                self.assertEqual(post('/api/column-values', **body, field='user_agent')['total'], 35)
                self.assertEqual(post('/api/column-values', **body, field='user_agent', value=None), {"total": 35, "events": 15})
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                store.connection.close()
                store.reviews.close()

    def test_request_timing_correlation_and_redaction(self):
        request = Request(self.url + "/api/reference",
                          data=json.dumps({"kind": "identity", "value": "private-identity-marker"}).encode(),
                          headers={"Content-Type": "application/json"})
        with self.assertLogs("kamotrace", level="DEBUG") as captured:
            with urlopen(request, timeout=15) as response:
                self.assertEqual(response.status, 200)
                request_id = response.headers["X-Request-ID"]
                self.assertEqual(json.load(response)["matches"], [])
            self.assertEqual(self.call("/api/reference", {"kind": "private-kind-marker", "value": "private-value-marker"})[0], 400)
            self.assertEqual(self.call("/api/events/private-record-marker?private-query-marker")[0], 400)
        self.assertRegex(request_id, r"^[0-9a-f]{16}$")
        output = "\n".join(captured.output)
        self.assertIn(f"request_id={request_id} operation=reference", output)
        self.assertIn(f"request_id={request_id} method=POST route=/api/reference status=200", output)
        self.assertIn("operation=reference.events", output)
        for field in ("lock_wait_ms", "execution_ms", "total_ms", "elapsed_ms", "bytes"):
            self.assertRegex(output, rf"{field}=\d+(?:\.\d+)?")
        self.assertIn("outcome=error", output)
        for private in ("private-query-marker", "private-record-marker", "private-identity-marker", "private-kind-marker", "private-value-marker"):
            self.assertNotIn(private, output)

    def test_reference_only_cards_do_not_wait_for_event_queries(self):
        contexts = [
            ({"kind": "ip", "value": "1.1.1.1", "account": "123", "region": "ap-southeast-3"}, {"inventory", "enrichment"}),
            ({"kind": "identity", "value": "arn:aws:iam::123:user/alice", "account": "123"}, set()),
            ({"kind": "machine", "value": "i-alpha", "account": "123", "region": "ap-southeast-3"}, {"inventory"}),
        ]
        # Simulate a long-running event query owning the Store lock. Reference-only
        # cards must still finish through the public HTTP endpoint, without history.
        with self.store.lock:
            for context, sources in contexts:
                status, card = self.call("/api/reference", {**context, "include_history": False})
                self.assertEqual(status, 200)
                self.assertFalse(card["history_included"])
                self.assertEqual({m["source"] for m in card["matches"]}, sources)
                self.assertFalse(any("event_count" in m.get("identity", {}) or "command_count" in m for m in card["matches"]))
        _, ip = self.call("/api/reference", {**contexts[0][0], "include_history": True})
        self.assertTrue(ip["history_included"])
        self.assertEqual([m["identity"]["event_count"] for m in ip["matches"] if m["source"] == "cloudtrail"], [1])
        _, identity = self.call("/api/reference", {**contexts[1][0], "include_history": True})
        self.assertEqual(sum(m["identity"]["event_count"] for m in identity["matches"]), 5)
        _, machine = self.call("/api/reference", {**contexts[2][0], "include_history": True})
        self.assertEqual({m["source"] for m in machine["matches"]}, {"inventory", "ssm"})
        for value in (0, "false", None, []):
            self.assertEqual(self.call("/api/reference", {**contexts[0][0], "include_history": value})[0], 400)

    def test_iam_inventory_cards_resolve_global_scope_groups_and_sts_roles(self):
        status, report = self.call("/api/inventory")
        self.assertEqual(status, 200)
        self.assertEqual(report["iam"]["groups"][0]["GroupName"], "investigators")
        for value in ("auditor", "AROAUDITOR", "arn:aws:iam::123:role/team/auditor",
                      "arn:aws:sts::123:assumed-role/auditor/test-session"):
            status, card = self.call("/api/reference", {"kind": "identity", "value": value, "account": "123",
                                                       "region": "ap-southeast-1", "include_history": False})
            self.assertEqual(status, 200)
            self.assertFalse(card["ambiguous"])
            match, = card["matches"]
            self.assertEqual(match["id"], "arn:aws:iam::123:role/team/auditor")
            self.assertEqual(match["region"], "global")
            custom, aws = match["iam_policies"]
            self.assertFalse(custom["aws_managed"])
            self.assertEqual(custom["PolicyVersionList"][1]["VersionId"], "v2")
            self.assertTrue(aws["aws_managed"])
            self.assertNotIn("PolicyVersionList", aws)
            self.assertIn("AssumeRolePolicyDocument", match["iam"])
        for value in ("arn:aws:sts::999:assumed-role/auditor/test-session", "arn:aws:sts::123:assumed-role/missing/test-session"):
            self.assertEqual(self.call("/api/reference", {"kind": "identity", "value": value, "include_history": False})[1]["matches"], [])
        _, user = self.call("/api/reference", {"kind": "identity", "value": "analyst", "include_history": False})
        self.assertEqual(user["matches"][0]["iam_groups"][0]["GroupName"], "investigators")
        self.assertEqual(user["matches"][0]["iam_policies"][0]["PolicyName"], "CaseRead")
        _, group = self.call("/api/reference", {"kind": "identity", "value": "arn:aws:iam::123:group/team/investigators", "include_history": False})
        self.assertEqual(group["matches"][0]["iam"]["GroupPolicyList"][0]["PolicyName"], "inline-group")
        self.assertEqual(self.call("/api/reference", {"kind": "identity", "value": "analyst", "account": "999", "include_history": False})[1]["matches"], [])

    def test_inventory_and_scope_aware_reference_cards(self):
        status, report = self.call("/api/inventory")
        self.assertEqual(status, 200)
        self.assertTrue(report["loaded"])
        self.assertEqual(report["resources"], self.inventory_report["resources"])
        self.assertEqual(report["errors"][0]["operation"], "describe_db_instances")
        self.assertEqual(report["metadata"]["completed_at_utc"], "2026-10-29T15:01:00Z")
        for kind, value in [("machine", "application"), ("ip", "10.0.1.5")]:
            status, card = self.call("/api/reference", {"kind": kind, "value": value})
            self.assertEqual(status, 200)
            self.assertTrue(card["ambiguous"])
            self.assertEqual({m["id"] for m in card["matches"]}, {"i-example", "i-other"})
            _, card = self.call("/api/reference", {"kind": kind, "value": value, "account": "123", "region": "us-east-1"})
            self.assertFalse(card["ambiguous"])
            self.assertEqual([m["id"] for m in card["matches"]], ["i-other"])
            _, card = self.call("/api/reference", {"kind": kind, "value": value, "account": "different-account"})
            self.assertEqual(card["matches"], [])
        _, role = self.call("/api/reference", {"kind": "identity", "value": "arn:aws:iam::123:role/application-role"})
        self.assertEqual({m["source"] for m in role["matches"]}, {"inventory"})
        _, session = self.call("/api/reference", {"kind": "identity", "value": "arn:aws:sts::123:assumed-role/application-role/session"})
        self.assertEqual(session["matches"], [])  # Never guess that a session belongs to a known role.
        _, identity = self.call("/api/reference", {"kind": "identity", "value": "arn:aws:iam::123:user/alice", "account": "123"})
        self.assertEqual(sum(m["identity"]["event_count"] for m in identity["matches"]), 5)
        self.assertEqual(identity["matches"][0]["identity"]["first_seen"], "2026-10-24 16:59:59+00")
        _, ip = self.call("/api/reference", {"kind": "ip", "value": "1.1.1.1", "region": "ap-southeast-3", "account": "123"})
        self.assertEqual({m["source"] for m in ip["matches"]}, {"inventory", "cloudtrail", "enrichment"})
        observed = next(m for m in ip["matches"] if m["source"] == "cloudtrail")
        self.assertEqual(observed["identity"]["event_count"], 1)  # Other account and missing scope excluded.
        _, machine = self.call("/api/reference", {"kind": "machine", "value": "i-alpha", "account": "123", "region": "ap-southeast-3"})
        self.assertEqual({m["source"] for m in machine["matches"]}, {"inventory", "ssm"})
        _, name = self.call("/api/reference", {"kind": "machine", "value": "ssm-worker", "account": "123", "region": "ap-southeast-3"})
        self.assertTrue(name["ambiguous"])
        self.assertEqual({m["id"] for m in name["matches"]}, {"i-alpha", "i-beta"})
        _, unknown = self.call("/api/reference", {"kind": "machine", "value": "application' OR 1=1 --"})
        self.assertEqual(unknown["matches"], [])
        for body in ({"kind": "sql", "value": "select"}, {"kind": "ip", "value": "not-an-ip"},
                     {"kind": "machine", "value": "x", "region": []}):
            self.assertEqual(self.call("/api/reference", body)[0], 400)
        self.assertEqual(self.call("/api/inventory", headers={"Origin": "https://attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/reference", {"kind": "machine", "value": "i-alpha"},
                                   headers={"Host": "attacker.invalid"})[0], 403)

    def test_ip_network_ranges_do_not_assert_resource_ownership(self):
        for address, expected in [
            ("10.0.1.127", {"vpc-test"}),
            ("10.0.1.128", {"vpc-test", "subnet-range"}),
            ("10.0.1.255", {"vpc-test", "subnet-range"}),
            ("10.0.2.0", {"vpc-test"}),
            ("10.1.0.0", set()),
            ("2001:0db8:1234:0080::1", {"vpc-test", "subnet-range"}),
            ("2001:db8:1234:81::", {"vpc-test"}),
            ("2001:db8:1234:100::", set()),
        ]:
            with self.subTest(address=address):
                status, card = self.call("/api/reference", {"kind": "ip", "value": address,
                    "account": "123", "region": "ap-southeast-3"})
                self.assertEqual(status, 200)
                self.assertEqual(card["matches"], [])
                self.assertEqual({m["id"] for m in card["network_matches"]}, expected)
                self.assertTrue(all("resource" not in m for m in card["network_matches"]))
        _, card = self.call("/api/reference", {"kind": "ip", "value": "10.0.1.129"})
        self.assertEqual({(m["id"], m["region"]) for m in card["network_matches"]}, {
            ("vpc-test", "ap-southeast-3"), ("vpc-test", "us-east-1"), ("subnet-range", "ap-southeast-3")})
        subnet = next(m["network"] for m in card["network_matches"] if m["kind"] == "Subnet")
        self.assertEqual((subnet["cidr"], subnet["vpc_id"], subnet["availability_zone"]),
                         ("10.0.1.128/25", "vpc-test", "ap-southeast-3a"))
        _, card = self.call("/api/reference", {"kind": "ip", "value": "10.0.1.129", "account": "other"})
        self.assertEqual(card["network_matches"], [])
        _, card = self.call("/api/reference", {"kind": "ip", "value": "10.0.1.5", "region": "ap-southeast-3"})
        self.assertEqual([m["id"] for m in card["matches"]], ["i-example"])
        self.assertEqual([m["id"] for m in card["network_matches"]], ["vpc-test"])
        self.assertFalse(card["ambiguous"])  # The containing VPC is not a competing resource owner.

    def test_serve_reports_startup_progress_and_ready_url(self):
        for transport in ("http", "stdio"):
            with self.subTest(transport=transport):
                self.check_startup(transport)

    def check_startup(self, transport):
        with tempfile.TemporaryDirectory() as temporary:
            process = subprocess.Popen([sys.executable, "-m", "kamotrace", "serve",
                "--case", str(self.database.with_suffix(".fixture-case.json")), "--ssm-export", str(self.ssm_export),
                "--enrichment", str(self.database.with_suffix(".enrichment.duckdb")),
                "--annotations", str(Path(temporary) / "reviews.sqlite3"), "--bind", "127.0.0.1", "--port", "0",
                *(["--mcp-transport", "stdio", "--inventory-export", str(self.inventory_export)] if transport == "stdio" else [])],
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
                    if line.startswith("  claude mcp add"):
                        break
                if transport == "http":
                    self.assertIn(f"MCP (HTTP): {url}/mcp", output)
                    self.assertIn(f"amp mcp add kamotrace {url}/mcp", output)
                    self.assertIn(f"claude mcp add --transport http kamotrace {url}/mcp", output)
                    async def session():
                        async with Client(url + "/mcp") as client:
                            result = await client.call_tool("describe_schema")
                            self.assertEqual(result.structured_content["first_event"], "2026-10-24T16:59:59+00:00")
                    anyio.run(session)
                else:
                    self.assertIn("MCP (stdio):", output)
                    for agent in ("amp", "claude"):
                        self.assertIn(f"{agent} mcp add kamotrace -- kamotrace mcp --url {url}", output)
                    with self.assertRaises(HTTPError) as error:
                        urlopen(url + "/mcp", timeout=15)
                    self.assertEqual(error.exception.code, 404)
                    error.exception.close()
                for stage in ("Opening evidence database (read-only)", "Validating findings/tags evidence identity",
                              "Loading IP enrichment", "Loading and linking SSM commands", "Loading Suzaku detections",
                              "Calculating event counts", "Binding HTTP server", "Startup complete in"):
                    self.assertIn(stage, output)
                self.assertIn(str(self.database.with_suffix(".fixture-case.json")), output)
                self.assertIn(str(self.database.with_suffix(".enrichment.duckdb")), output)
                self.assertIn(str(self.ssm_export), output)
                self.assertRegex(output, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4} INFO")
                with urlopen(url + "/api/meta", timeout=15) as response:
                    self.assertEqual(json.load(response)["total"], 5)
                with urlopen(url + "/api/inventory", timeout=15) as response:
                    inventory = json.load(response)
                    self.assertEqual(inventory["loaded"], transport == "stdio")
                    if transport == "http":
                        self.assertEqual(inventory["resources"], [])
                        self.assertIsNone(inventory["metadata"])
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
        self.assertEqual((listed[second]["context"], listed[second]["events"], listed[nid]["context"]),
                         ({**context, "case_context": {k: self.store.coverage[k] for k in ("case_id", "selection_id")}}, 1, None))
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

    def test_inventory_category_search_pages_and_response_limits(self):
        def query(**body):
            status, result = self.call("/api/inventory", body)
            self.assertEqual(status, 200, result)
            return result

        original = self.call("/api/inventory")[1]
        overview = query()
        self.assertNotIn("data", overview)
        categories = {row["category"]: row for row in overview["categories"]}
        self.assertEqual(categories["resources"]["total"], 4)
        self.assertFalse(categories["eks_coverage"]["available"])
        self.assertTrue(categories["relationships"]["available"])
        self.assertEqual(categories["relationships"]["total"], 0)
        self.assertLess(len(json.dumps(overview).encode()), 3000)
        resources = query(category="resources", search="APPLICATION", account="123", region="ap-southeast-3", kind="EC2")
        self.assertEqual([row["id"] for row in resources["data"]], ["i-example"])
        self.assertNotIn("details", resources["data"][0])
        self.assertEqual(query(category="resources", account="different-account")["total"], 0)
        self.assertEqual(query(category="resources", search="t3.small")["total"], 0)  # Not nested configuration search.
        self.assertEqual(query(category="resources", search="' OR true --")["total"], 0)
        detail = query(category="resources", resource_id="i-example", include_details=True)
        self.assertEqual(detail["data"], [original["resources"][0]])
        self.assertEqual(query(category="forwarding_paths", resource_id="i-example", include_details=True)["data"], original["forwarding_paths"])
        iam = query(category="iam.roles", search="AUDITOR", region="global", include_details=True)
        self.assertEqual(iam["data"], original["iam"]["roles"])
        self.assertEqual(query(category="iam.roles", region="ap-southeast-3")["total"], 0)
        for category, field in (("users", "UserId"), ("roles", "RoleId"), ("groups", "GroupId")):
            identifier = original["iam"][category][0][field]
            exact = query(category="iam." + category, resource_id=identifier)
            self.assertEqual(exact["total"], 1)
            self.assertEqual(exact["data"][0][field], identifier)
            self.assertEqual(query(category="iam." + category, search=identifier.lower())["total"], 1)
        action = original["forwarding_paths"][0]
        with patch.dict(self.store.inventory.report, {"listener_actions": [action]}):
            for field in ("listener_id", "rule_id", "target_group_id"):
                self.assertEqual(query(category="listener_actions", resource_id=action[field])["data"][0][field], action[field])
                self.assertEqual(query(category="listener_actions", search=action[field].upper())["total"], 1)
            self.assertEqual(query(category="listener_actions", search=action["load_balancer_name"].upper())["total"], 1)
            self.assertEqual(query(category="listener_actions", resource_id=action["load_balancer_name"])["total"], 0)
        meta = query(category="metadata", resource_id="limitations", include_details=True)
        self.assertEqual(meta["data"], [{"id": "limitations", "value": original["metadata"]["limitations"]}])
        for body in ({"search": "application"}, {"category": "raw.path"}, {"category": "resources", "page": True},
                     {"category": "resources", "size": 101}, {"category": "resources", "page": 0},
                     {"category": "resources", "account": []}, {"category": "resources", "include_details": "false"},
                     {"category": "resources", "sql": "SELECT *"}):
            with self.subTest(body=body):
                self.assertEqual(self.call("/api/inventory", body)[0], 400)

        large = [{"id": f"synthetic-{i:02}", "name": "Bulk", "kind": "EC2", "region": "ap-southeast-3",
                  "details": {"configuration": "界" * 6000}} for i in reversed(range(53))]
        with patch.dict(self.store.inventory.report, {"resources": large}):
            self.assertLess(len(json.dumps(query()).encode()), 3000)
            pages = [query(category="resources", search="bulk", size=25, page=p) for p in (1, 2, 3)]
            self.assertEqual([page["total"] for page in pages], [53, 53, 53])
            self.assertEqual([page["next_page"] for page in pages], [2, 3, None])
            self.assertEqual([r["id"] for page in pages for r in page["data"]], [f"synthetic-{i:02}" for i in range(53)])
            status, error = self.call("/api/inventory", {"category": "resources", "resource_id": "synthetic-00", "include_details": True, "size": 1})
            self.assertEqual(status, 400)
            self.assertIn("nothing was truncated", error["error"])
            self.assertEqual(query(category="resources", resource_id="synthetic-00")["total"], 1)
            self.assertEqual(self.call("/api/inventory")[1]["resources"], large)  # Full browser report stays compatible.
        moderate = [{"id": f"sized-{i}", "details": {"configuration": "x" * 12000}} for i in range(2)]
        with patch.dict(self.store.inventory.report, {"resources": moderate}):
            self.assertEqual(self.call("/api/inventory", {"category": "resources", "include_details": True, "size": 2})[0], 400)
            first = query(category="resources", include_details=True, size=1)
            self.assertEqual((first["total"], first["next_page"], first["data"]), (2, 2, moderate[:1]))
            self.assertEqual(query(category="resources", include_details=True, size=1, page=2)["data"], moderate[1:])
        self.assertEqual(self.call("/api/inventory")[1], original)

    def test_mcp_sessions_share_the_browser_servers_reviews(self):
        # Real MCP sessions over HTTP and stdio. The adapter holds no database handle: every agent
        # write must be visible through the browser's own API immediately, and vice versa.
        def rest(path, body=None):
            status, result = self.call(path, body)
            self.assertEqual(status, 200, result)
            return result

        async def session(transport):
            async with Client(transport) as client:
                async def tool(name, **arguments):
                    result = await client.call_tool(name, arguments)
                    return ("error", result.content[0].text) if result.is_error else result.structured_content

                names = {t.name for t in (await client.list_tools()).tools}
                overview = await tool("get_inventory")
                self.assertTrue(overview["loaded"])
                self.assertNotIn("data", overview)
                inventory = await tool("get_inventory", category="resources", search="APPLICATION",
                                       region="us-east-1", size=1, include_details=True)
                self.assertEqual(inventory["total"], 1)
                self.assertEqual(inventory["data"], [self.inventory_report["resources"][1]])
                self.assertEqual((await tool("get_inventory", search="application"))[0], "error")
                pods = await tool("search_eks_pods", account="123", region="us-east-1", cluster="uncollected")
                self.assertEqual(pods["total"], 0)
                self.assertEqual(pods["coverage"]["datasets_total"], 0)
                orphan_page = await tool("list_ssm_orphan_reviews", page=1)
                self.assertIn("next_page", orphan_page)
                self.assertEqual((await tool("get_ssm_orphan_review", entry_id="nonexistent"))[0], "error")
                self.assertLessEqual({"describe_schema", "search_events", "get_event", "tag_events", "untag_events",
                                      "create_note", "edit_note", "link_note_events", "unlink_note_events",
                                      "search_ssm_commands", "get_ssm_command", "search_ssm_log", "get_ssm_log_entry", "edit_ssm_log_entry"}, names)
                self.assertEqual(await tool("list_detections"), {"run": None, "iwatobi": None, "guardduty": None, "rules": []})
                schema = await tool("describe_schema")
                self.assertIn("not_missing", schema["operators"])
                self.assertEqual(schema["timezone"], "UTC")
                self.assertTrue(schema["evidence_read_only"])
                projected = await tool("search_events", query={"raw_fields": ["raw.requestParameters.number"],
                    "filters": [{"field": "raw.requestParameters.number", "op": "eq", "value": "9007199254740993"}]})
                self.assertEqual(projected["total"], 5)
                self.assertTrue(all(r["raw_fields"]["raw.requestParameters.number"]["value"] == "9007199254740993"
                    for r in projected["events"]))
                self.assertEqual((await tool("summarize_field", field="raw.requestParameters.number"))["top"],
                    [{"value": "9007199254740993", "events": 5}])
                self.assertTrue(schema["annotations_writable"])
                self.assertNotIn("facets", schema)
                self.assertNotIn("timezones", schema)
                self.assertEqual(schema["first_event"], "2026-10-24T16:59:59+00:00")
                self.assertEqual(schema["pipeline_fields"], rest("/api/meta")["pipeline_fields"])
                # The end-user skill's pipeline example, through both real MCP transports.
                pipeline_query = {"timezone": "Asia/Singapore", "start": "2026-10-24T00:00:00+08:00",
                                  "end": "2026-10-26T00:00:00+08:00", "pipeline_version": 1,
                                  "pipeline": 'event_name = "SendCommand" OR event_name = "StartSession" | search "ssm.amazonaws.com"'}
                pipeline_result = await tool("search_events", query=pipeline_query,
                                             sort=[{"field": "time_local", "dir": "asc"}])
                expected_ids = ["event-0", "event-1", "event-2"]
                self.assertEqual([event["event_id"] for event in pipeline_result["events"]], expected_ids)
                self.assertEqual(pipeline_result["total"], 3)
                self.assertEqual(sorted(event["event_id"] for event in rest("/api/events", pipeline_query)["data"]), expected_ids)
                summary = await tool("summarize_field", field="event_name", query=pipeline_query)
                self.assertEqual(summary["total"], 3)
                self.assertEqual(summary["top"], [{"value": "SendCommand", "events": 2}, {"value": "StartSession", "events": 1}])
                self.assertEqual((await tool("event_histogram", query=pipeline_query))["total"], 3)
                pipeline_note = await tool("create_note", body="Pipeline example", query=pipeline_query,
                                           hashes=[event["record_sha256"] for event in pipeline_result["events"]])
                stored = {note["id"]: note for note in rest("/api/reviews")["annotations"]}[pipeline_note["id"]]
                self.assertEqual(stored["context"]["pipeline"], pipeline_query["pipeline"])
                self.assertEqual(stored["context"]["pipeline_version"], 1)
                self.assertEqual(stored["events"], 3)
                self.assertTrue((await tool("delete_note", id=pipeline_note["id"], updated=pipeline_note["updated"]))["deleted"])
                for invalid, message in [({**pipeline_query, "pipeline_version": 2}, "Unsupported pipeline_version"),
                                         ({"pipeline_version": 2}, "Unsupported pipeline_version"),
                                         ({"pipeline": None, "pipeline_version": 2}, "Unsupported pipeline_version"),
                                         ({**pipeline_query, "pipeline": 'region = "x" |'}, "line 1, column")]:
                    for name, arguments in [("search_events", {}), ("summarize_field", {"field": "event_name"}),
                                            ("event_histogram", {}),
                                            ("create_note", {"body": "Invalid pipeline", "hashes": [pipeline_result["events"][0]["record_sha256"]]})]:
                        error = await tool(name, query=invalid, **arguments)
                        self.assertEqual(error[0], "error", (name, error))
                        self.assertIn(message, error[1])
                singapore = await tool("describe_schema", timezone="Asia/Singapore", include_timezones=True)
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
                self.assertIn(created["id"], [n["id"] for n in (await tool("list_notes", search="Edited"))["data"]])
                self.assertEqual((await tool("read_note_text", id=created["id"]))["text"], "Edited")
                context = json.loads((await tool("read_note_text", id=created["id"], field="context"))["text"])
                self.assertEqual(context["timezone"], "Asia/Jakarta")
                self.assertEqual((await tool("search_events", query={"filters": [{"field": "event_name", "op": "in",
                    "value": ["StartSession", "UpdateInstanceInformation"]}]}))["total"], 2)
                self.assertEqual((await tool("search_events", query={"filters": [{"field": "document_name", "op": "missing",
                    "value": None}]}))["total"], 5)
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
                log = await tool("search_ssm_log", search="alpha stdout")
                budgeted = await client.call_tool("search_ssm_log", {})
                self.assertLess(len(budgeted.model_dump_json().encode()), 80000)
                self.assertEqual((await tool("read_ssm_log_text", entry_id=log["data"][0]["entry_id"], field="stdout"))["text"],
                                 "alpha stdout <script>neverRun()</script>")
                entry = log["data"][0]
                args = {"entry_id": entry["entry_id"], "text": "echo synthetic\n",
                        "tags": ["decoded"], "finding": "Agent note: statically decoded Base64 as UTF-8; not executed.",
                        "updated": entry["review"]["updated"]}
                review = await tool("edit_ssm_log_entry", **args)
                self.assertEqual(review["tags"], ["decoded"])
                self.assertEqual(review["text"], "echo synthetic\n")
                self.assertEqual((await tool("edit_ssm_log_entry", **args))[0], "error")
                reread = (await tool("search_ssm_log", search="alpha stdout"))["data"][0]
                self.assertEqual(reread["review"], review)
                self.assertEqual(reread["stdout"], entry["stdout"])
                found = await tool("search_ssm_log", search="STATICALLY decoded", search_scope="enhanced")
                self.assertEqual([e["entry_id"] for e in found["data"]], [entry["entry_id"]])
                self.assertEqual((await tool("search_ssm_log", search="statically decoded", search_scope="raw"))["total"], 0)
                self.assertEqual((await tool("get_ssm_log_entry", entry_id=entry["entry_id"]))["review"], review)
                analysis = await tool("read_ssm_log_text", entry_id=entry["entry_id"], field="analysis")
                self.assertIn("decoder_version", json.loads(analysis["text"]))
                self.assertEqual((await tool("get_ssm_log_entry", entry_id="0" * 64))[0], "error")
                continued = await tool("search_ssm_log", search="stdout", page=2)
                self.assertEqual(continued[0], "error")
                self.assertIn("refresh the search", continued[1])
                self.assertEqual((await tool("search_ssm_log", search="stdout", page=2, revision=found["revision"]))["data"], [])
                self.assertEqual((await tool("edit_ssm_log_entry", **{**args, "entry_id": "0" * 64}))[0], "error")
                self.assertEqual((await tool("delete_note", id=created["id"], updated=note["updated"]))["deleted"], True)
                self.assertNotIn(created["id"], [n["id"] for n in rest("/api/reviews")["annotations"]])
                batch = await tool("edit_ssm_log_entries", items=[{**args, "updated": review["updated"]},
                    {**args, "entry_id": "0" * 64}])
                self.assertEqual([r["status"] for r in batch["results"]], ["ok", "missing"])
                reference = await tool("lookup_reference", kind="ip", value="10.0.1.5")
                self.assertTrue(reference["ambiguous"])
                self.assertFalse(reference["history_included"])
                scoped = await tool("lookup_reference", kind="ip", value="10.0.1.5", account="123", region="us-east-1")
                self.assertFalse(scoped["ambiguous"])
                self.assertEqual([r["id"] for r in scoped["matches"]], ["i-other"])
                self.assertEqual(scoped["snapshot"]["completed_at_utc"], "2026-10-29T15:01:00Z")
                for dataset, fields in (("events", ["id", "raw_json"]), ("ssm", ["entry_id", "stdout", "review", "events"])):
                    exported = await tool("create_export", dataset=dataset, fields=fields)
                    self.assertTrue(exported["ready"], exported)
                    with urlopen(exported["download_url"]) as downloaded:
                        data = downloaded.read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), exported["sha256"])
                    self.assertEqual(len(data.splitlines()) - 1, exported["rows"])
                    self.assertLess(len(json.dumps(exported).encode()), 2000)
                self.store.exports.close()
                self.store.exports = None

        for transport in (self.url + "/mcp", StdioServerParameters(
                command=sys.executable, args=["-m", "kamotrace", "mcp", "--url", self.url])):
            with self.subTest(transport=str(transport)):
                anyio.run(session, transport)

    def test_mcp_http_get_declines_optional_event_stream(self):
        for accept in ("*/*", "text/event-stream", "application/json"):
            with self.subTest(accept=accept):
                request = Request(self.url + "/mcp", headers={"Accept": accept})
                with self.assertRaises(HTTPError) as raised:
                    urlopen(request, timeout=2)
                with raised.exception as response:
                    self.assertEqual(response.code, 405)
                    self.assertEqual(response.headers["Allow"], "POST, DELETE")
                    self.assertEqual(response.read(), b"")
        for headers in ({"Host": "evil.example"}, {"Origin": "https://evil.example"}):
            self.assertEqual(self.call("/mcp", headers=headers)[0], 403)

    def test_mcp_http_discovery_does_not_advertise_streaming_subscriptions(self):
        status, response = self.call("/mcp", {
            "jsonrpc": "2.0", "id": "discover", "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                  "io.modelcontextprotocol/clientInfo": {"name": "contract-test", "version": "1"},
                                  "io.modelcontextprotocol/clientCapabilities": {}}},
        }, headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28",
                    "MCP-Method": "server/discover"})
        self.assertEqual(status, 200, response)
        capabilities = response["result"]["capabilities"]
        for name in ("tools", "prompts", "resources"):
            self.assertFalse(capabilities[name].get("listChanged", False), name)
        self.assertFalse(capabilities["resources"].get("subscribe", False))

    def test_mcp_http_rejects_cross_site_requests_and_oversized_bodies(self):
        for headers in ({"Host": "evil.example"}, {"Origin": "https://evil.example"}):
            self.assertEqual(self.call("/mcp", {}, headers=headers)[0], 403)
        self.assertEqual(self.call("/mcp", {}, headers={"Content-Length": "1048577"})[0], 400)
        self.assertEqual(self.call("/mcp", {}, headers={"Content-Length": "-1"})[0], 400)

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
            http_server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
            http_thread.start()
            try:
                for text, expected in [
                    ('lead in ("rule-low", "rule-high")', ["event-0", "event-2"]),
                    ('lead = "rule-low" AND lead = "rule-high"', ["event-0"]),
                    ('lead != "rule-low"', ["event-1", "event-3", "event-4"]),
                    ('lead = "unknown"', []),
                    ('lead = "rule-chain" OR lead = "rule-high"', ["event-0", "event-2"])]:
                    body = {"pipeline": text, "pipeline_version": 1}
                    for path in ("/api/events", "/api/histogram"):
                        request = Request(f"http://127.0.0.1:{http_server.server_port}" + path,
                                          data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
                        with urlopen(request, timeout=15) as response:
                            result = json.load(response)
                        if path == "/api/events":
                            self.assertEqual(sorted(r["event_id"] for r in result["data"]), expected)
                            self.assertEqual(result["last_row"], len(expected))
                        else:
                            self.assertEqual(result["total"], len(expected))
            finally:
                http_server.shutdown()
                http_thread.join()
                http_server.server_close()
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
        self.assertEqual(self.call("/api/detections")[1], {"run": None, "iwatobi": None, "guardduty": None, "rules": []})

    def test_large_detection_sidecar_preserves_all_rules_and_lists(self):
        sidecar = Path(self.temp.name) / "bulk.detections.duckdb"
        from kamotrace.suzaku import evidence_identity
        identity = evidence_identity(self.store.connection)
        run = {"schema_version": 1, "evidence_source_sha256": identity[0], "evidence_records": identity[1]}
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

    def test_special_use_ip_classification_without_sidecar(self):
        cases = {
            "(private)": ["10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
                          "192.168.0.0", "192.168.255.255", "fc00::", "FD12:0000::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                          "::ffff:192.168.1.2"],
            "(loopback)": ["127.4.3.2", "::1"],
            "(link-local)": ["169.254.3.4", "fe80::1234"],
            "(multicast)": ["224.0.0.1", "239.255.255.255", "ff02::1"],
            "(unspecified)": ["0.0.0.0", "::"],
            "(shared address space)": ["100.64.0.0", "100.127.255.255"],
            "(documentation)": ["192.0.2.1", "198.51.100.8", "203.0.113.10", "2001:db8::1", "3fff::1"],
            "(benchmarking)": ["198.18.0.1", "2001:2::1"],
            "(limited broadcast)": ["255.255.255.255"],
            "(reserved)": ["240.0.0.1", "fe00::1"],
            "(site-local)": ["fec0::1"],
            "(unmapped / service / private)": ["9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
                                                "192.167.255.255", "192.169.0.0", "100.63.255.255", "100.128.0.0",
                                                "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8",
                                                "ec2.amazonaws.com", "not-an-ip"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, database = root / "events.json", root / "case.duckdb"
            expected = {ip: label for label, ips in cases.items() for ip in ips}
            source.write_text(json.dumps({"Records": [{"eventID": f"scope-{i}", "eventTime": "2026-10-24T01:00:00Z",
                "eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com", "sourceIPAddress": ip,
                "awsRegion": "us-east-1"} for i, ip in enumerate(expected)]}), encoding="utf-8")
            build(source, database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            store = Store(database)
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

                rows = request("/api/events", {"size": 100})["data"]
                self.assertEqual({row["source_ip"]: row["country"] for row in rows}, expected)
                self.assertEqual(len(rows), len(expected))  # No duplicate joins.
                self.assertTrue(all(row["city"] is None and row["asn"] is None and row["isp"] is None for row in rows))
                for label, ips in cases.items():
                    result = request("/api/events", {"filters": [{"field": "country", "op": "eq", "value": label}]})
                    self.assertEqual(result["last_row"], len(ips), label)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                store.connection.close()
                store.reviews.close()
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

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
            "2001:db8::1": ("(documentation)", None, None, "IPv6 Example", "spur.residential=false"),
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

    def test_older_annotation_sidecar_is_rejected_unchanged(self):
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
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "legacy Findings sidecar"):
            Store(self.database, annotations=path)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        # An old sidecar cannot be adopted by a different fresh case either.
        source = Path(self.temp.name) / "other.json"
        source.write_text(json.dumps({"Records": [{"eventID": "x", "eventTime": "2026-10-24T00:00:00Z"}]}), encoding="utf-8")
        build(source, Path(self.temp.name) / "other.duckdb")
        with self.assertRaisesRegex(ValueError, "legacy Findings sidecar"):
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

    def test_ssm_log_outputs_exact_links_and_review_contract(self):
        status, result = self.call("/api/ssm-log", {})
        self.assertEqual(status, 200)
        # Six sheet rows plus two requests. SendCommand event-0/event-2 match account+region+command ID, so
        # they belong to each command-multi machine/plugin entry instead of being separate activity; event-3
        # has the same command ID in another account and stays its own request entry, as does StartSession.
        self.assertEqual(result["total"], 8)
        self.assertEqual([r["time_ms"] for r in result["data"]], sorted(r["time_ms"] for r in result["data"]))
        requests = [r for r in result["data"] if r["operation"] != "Command output"]
        self.assertEqual(sorted((r["operation"], r["events"][0]["event_id"]) for r in requests),
                         [("SendCommand", "event-3"), ("StartSession", "event-1")])
        self.assertEqual(requests[1]["command_id"], "command-multi")
        outputs = [r for r in result["data"] if r["operation"] == "Command output"]
        self.assertEqual(sorted((r["instance_id"], r["plugin"]) for r in outputs if r["region"] == "ap-southeast-3"),
            [("i-alpha", "second-step"), ("i-alpha", "shell"), ("i-beta", "fallback-step"), ("i-beta", "shell"), ("i-missing", None)])
        for row in outputs:
            linked = {e["event_id"]: e for e in row["events"]}
            if row["region"] != "ap-southeast-3":
                continue
            self.assertEqual(set(linked), {"event-0", "event-2", "supplement-only"})
            # The linked request keeps its exact CloudTrail parameters (precision preserved); polls carry none.
            self.assertEqual(linked["event-0"]["request"], '{"number": 9007199254740993, "instanceId": "i-example"}')
            self.assertIsNone(linked["supplement-only"]["request"])
        # Raw search reaches the linked request's parameters inside every matching output entry.
        found = self.call("/api/ssm-log", {"search": "i-example", "search_scope": "raw"})[1]
        self.assertEqual((found["total"], sum(r["region"] == "us-east-1" for r in found["data"])), (7, 0))
        self.assertEqual(self.call("/api/ssm-log", {"search": "i-example", "search_scope": "enhanced"})[1]["total"], 0)
        alpha = next(r for r in outputs if r["instance_id"] == "i-alpha" and r["plugin"] == "shell")
        missing = next(r for r in outputs if r["instance_id"] == "i-missing")
        combined = next(r for r in outputs if r["plugin"] == "fallback-step")
        self.assertEqual((alpha["stdout"], alpha["stderr"]), ("alpha stdout <script>neverRun()</script>", ""))
        self.assertEqual((missing["stdout"], missing["stderr"], missing["combined_output"]), (None, None, None))
        self.assertEqual((combined["stdout"], combined["stderr"], combined["combined_output"]), (None, None, "mixed stdout/stderr"))
        self.assertEqual(next(r for r in outputs if r["region"] == "us-east-1")["events"], [])
        self.assertEqual({e["event_id"] for e in alpha["events"]}, {"event-0", "event-2", "supplement-only"})
        supplemental = next(e for e in alpha["events"] if e["id"] is None)
        self.assertEqual(supplemental["source"], "Supplemental SSM export")
        self.assertIn("raw_json", self.call("/api/ssm-event", {"key": supplemental["key"]})[1])
        body = {"entry_id": missing["entry_id"], "text": "<script>plaintext only</script>",
                "tags": ["log-only", "log-only"], "finding": "Missing output, not empty output", "updated": missing["review"]["updated"]}
        status, saved = self.call("/api/ssm-log-review", body)
        self.assertEqual(status, 200)
        self.assertEqual(saved["tags"], ["log-only"])
        self.assertEqual(self.call("/api/ssm-log-review", body)[0], 400)
        self.assertEqual(self.call("/api/ssm-log", {"search": "i-missing"})[1]["data"][0]["review"], saved)
        for bad in ({"entry_id": "0" * 64}, {"tags": ["Bad Tag"]}, {"text": "x" * 30001},
                    {"finding": None}, {"tags": ["a"] * 101}):
            self.assertEqual(self.call("/api/ssm-log-review", {**body, "updated": saved["updated"], **bad})[0], 400)
        self.assertEqual(self.call("/api/ssm-log", {"page": 2})[1]["data"], [])
        for bad in ({"page": 0}, {"page": True}, {"search": []}, {"start": "2026-10-25"},
                    {"start": "2026-10-26T00:00:00Z", "end": "2026-10-25T00:00:00Z"}):
            self.assertEqual(self.call("/api/ssm-log", bad)[0], 400)
        sliced = self.call("/api/ssm-log", {"start": "2026-10-24T17:00:00Z", "end": "2026-10-24T17:00:01Z"})[1]
        self.assertEqual(sliced["total"], 7)

    def test_ssm_log_failed_requests_sessions_without_export_and_pagination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, database = root / "source.json", root / "source.duckdb"
            events = [{"eventID": f"request-{i}", "eventTime": f"2026-10-24T17:{i // 60:02}:{i % 60:02}Z",
                "eventSource": "ssm.amazonaws.com", "eventName": ["SendCommand", "StartSession", "ResumeSession", "TerminateSession"][i % 4],
                "recipientAccountId": "123", "awsRegion": "eu-west-1", "errorCode": "AccessDenied",
                "requestParameters": {"command": "plaintext", "sessionId": "s-exact",
                    **({"instanceIds": ["i-denied-a", "i-denied-b"]} if i % 4 == 0 else {"target": "i-session-target"})}}
                for i in range(105)]
            source.write_text(json.dumps({"Records": events}))
            build(source, database)
            store = Store(database)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def post(path, body):
                with urlopen(Request(f"http://127.0.0.1:{server.server_port}" + path,
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                    return json.load(response)

            try:
                first, last = post("/api/ssm-log", {}), post("/api/ssm-log", {"page": 2})
                reference = post("/api/reference", {"kind": "machine", "value": "i-session-target",
                    "include_history": False, "projection": "summary"})
                self.assertFalse(reference["inventory_loaded"])
                self.assertFalse(reference["history_included"])
                self.assertEqual(reference["matches"], [])
                self.assertFalse(first["loaded"])
                self.assertEqual((first["total"], len(first["data"]), len(last["data"])), (105, 100, 5))
                self.assertEqual(len({e["entry_id"] for e in first["data"] + last["data"]}), 105)
                self.assertLess(first["data"][-1]["time_ms"], last["data"][0]["time_ms"])
                self.assertEqual({e["operation"] for e in first["data"]}, {"SendCommand", "StartSession", "ResumeSession", "TerminateSession"})
                for entry in first["data"]:
                    self.assertIsNone(entry["command_id"])
                    self.assertIsNone(entry["command_key"])
                    self.assertIsNone(entry["stdout"])
                    self.assertEqual(entry["status"], "Failed request")
                    self.assertEqual(entry["events"][0]["error"], "AccessDenied")
                    self.assertEqual(entry["instance_id"], "i-denied-a, i-denied-b" if entry["operation"] == "SendCommand"
                                     else "i-session-target")
                entry = first["data"][0]
                review = post("/api/ssm-log-review", {"entry_id": entry["entry_id"], "text": "Unlinked request",
                    "tags": ["failed"], "finding": "Denied, not executed", "updated": None})
                self.assertEqual(post("/api/ssm-log", {})["data"][0]["review"], review)
                original = post("/api/ssm-event", {"key": entry["events"][0]["key"]})
                self.assertEqual(json.loads(original["raw_json"]), events[0])
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                store.reviews.close()
                store.connection.close()

    def test_ssm_log_scoped_search_revision_continuation_and_exact_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, database, export = root / "source.json", root / "source.duckdb", root / "export.json"
            # 230 linked requests (> two pages) plus one unrelated non-SSM event; request 5 has escaped characters.
            events = [{"eventID": f"req-{i:03d}", "eventTime": f"2026-10-24T17:{i // 60:02}:{i % 60:02}Z",
                "eventSource": "ssm.amazonaws.com", "eventName": "SendCommand", "recipientAccountId": "123",
                "awsRegion": "eu-west-1", "requestParameters": {"instanceIds": ["i-scope"], "commands": [
                    'Write-Output "C:\\Temp\\Mixed"' if i == 5 else f"echo request-{i:03d}"]}} for i in range(230)]
            events.append({"eventID": "unrelated", "eventTime": "2026-10-24T18:00:00Z", "eventSource": "ec2.amazonaws.com",
                           "eventName": "DescribeInstances", "recipientAccountId": "123", "awsRegion": "eu-west-1"})
            source.write_text(json.dumps({"Records": events}))
            build(source, database)
            command = {"CommandId": "cmd-late", "DocumentName": "AWS-RunShellScript", "RequestedDateTime": "2026-10-24T19:00:00Z",
                       "Status": "Success", "InstanceIds": ["i-late"], "Parameters": {"commands": ["echo ZGVjb2Rl | base64 -d"]}}
            export.write_text(json.dumps({"account_id": "123", "commands": [{"region": "eu-west-1", "record": command,
                "base64_enrichment": [{"parameter": "commands", "value_index": 0, "decodings": [
                    {"status": "decoded_utf8", "decoded_text": "DecodedOnlyTerm", "nested_decodings": []}]}]}],
                "invocations": [], "invocation_details": [{"region": "eu-west-1", "record": {"CommandId": "cmd-late",
                    "InstanceId": "i-late", "PluginName": "shell", "Status": "Success", "StandardOutputContent": "late stdout",
                    "StandardErrorContent": ""}}]}))
            store = Store(database, annotations=root / "reviews.sqlite3", ssm_export=export)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def post(path, body, expect=200):
                request = Request(f"http://127.0.0.1:{server.server_port}" + path, data=json.dumps(body).encode(),
                                  headers={"Content-Type": "application/json"})
                try:
                    with urlopen(request) as response:
                        status, result = response.status, json.load(response)
                except HTTPError as error:
                    with error:
                        status, result = error.code, json.load(error)
                self.assertEqual(status, expect, result)
                return result

            def ids(body):
                result = post("/api/ssm-log", body)
                return result["total"], [e["entry_id"] for e in result["data"]]

            try:
                everything = post("/api/ssm-log", {})
                order = everything["data"] + post("/api/ssm-log", {"page": 2})["data"] + post("/api/ssm-log", {"page": 3})["data"]
                summaries, page = [], 1
                while page:
                    part = post("/api/ssm-log", {"projection": "summary", "page": page})
                    self.assertLess(len(json.dumps(part).encode()), 24001)
                    self.assertTrue(all("events" not in e for e in part["data"]))
                    summaries.extend(e["entry_id"] for e in part["data"])
                    page = part["next_page"]
                self.assertEqual(summaries, [e["entry_id"] for e in order])
                self.assertEqual((everything["total"], len({e["entry_id"] for e in order})), (231, 231))
                request = [e for e in order if e["operation"] == "SendCommand"]  # request[i] is req-i, oldest first.
                late = next(e for e in order if e["operation"] == "Command output")
                unrelated = store.connection.execute("SELECT record_sha256 FROM events WHERE event_id='unrelated'").fetchone()[0]
                post("/api/ssm-log-review", {"entry_id": request[150]["entry_id"], "text": "Interp-Unique line\nbreak",
                                             "tags": [], "finding": "", "updated": None})
                post("/api/ssm-log-review", {"entry_id": request[160]["entry_id"], "text": "", "tags": ["mark-unique"],
                                             "finding": "", "updated": None})
                post("/api/ssm-log-review", {"entry_id": request[170]["entry_id"], "text": "", "tags": [],
                                             "finding": "Finding-Unique", "updated": None})
                post("/api/reviews", {"action": "tag", "slug": "event-label-unique", "color": "#123456",
                                      "hashes": [request[180]["events"][0]["record_sha256"]]})
                note = post("/api/reviews", {"action": "annotate", "body": "Event **finding** unique",
                                             "hashes": [request[190]["events"][0]["record_sha256"]]})
                # Each enhanced-only term is found beyond the first page, by Both and Enhanced but not Raw.
                for term, entry in (("interp-UNIQUE", request[150]), ("mark-unique", request[160]), ("finding-unique", request[170]),
                                    ("event-label-unique", request[180]), ("**finding** UNIQUE", request[190]),
                                    ("decodedonlyterm", late)):
                    for scope in ("both", "enhanced"):
                        self.assertEqual(ids({"search": term, "search_scope": scope}), (1, [entry["entry_id"]]), (term, scope))
                    self.assertEqual(ids({"search": term, "search_scope": "raw"}), (0, []), term)
                # Raw-only terms, including literal quotes/backslashes that serialized JSON would have escaped.
                for term, entry in (("c:\\temp\\mixed", request[5]), ('"C:\\', request[5]), ("late stdout", late)):
                    self.assertEqual(ids({"search": term, "search_scope": "raw"}), (1, [entry["entry_id"]]), term)
                    self.assertEqual(ids({"search": term}), (1, [entry["entry_id"]]), term)
                    self.assertEqual(ids({"search": term, "search_scope": "enhanced"}), (0, []), term)
                # Event tags/findings are shown per linked event, distinct from the entry's own review.
                shown = post("/api/ssm-log", {"search": "unique", "search_scope": "enhanced"})
                self.assertEqual([e["entry_id"] for e in shown["data"]], [request[i]["entry_id"] for i in (150, 160, 170, 180, 190)])
                tagged, noted = shown["data"][3], shown["data"][4]
                self.assertEqual((tagged["events"][0]["tags"], tagged["review"]["tags"]), ([{"slug": "event-label-unique", "color": "#123456"}], []))
                self.assertEqual(([n["id"] for n in noted["events"][0]["findings"]], noted["review"]["finding"]), ([note["id"]], ""))

                # Continuation: a review-dependent search needs page 1's revision and goes stale on relevant writes.
                both = {"search": "echo request", "search_scope": "both"}
                first = post("/api/ssm-log", both)
                self.assertTrue(first["review_dependent"])
                self.assertEqual(first["total"], 229)
                self.assertIn("refresh", post("/api/ssm-log", {**both, "page": 2}, 409)["error"])
                post("/api/reviews", {"action": "tag", "slug": "elsewhere", "color": "#654321", "hashes": [unrelated]})
                second = post("/api/ssm-log", {**both, "page": 2, "revision": first["revision"]})  # Unlinked event: unaffected.
                post("/api/ssm-log-review", {"entry_id": request[10]["entry_id"], "text": "edited before the boundary",
                                             "tags": [], "finding": "", "updated": None})
                stale = post("/api/ssm-log", {**both, "page": 3, "revision": first["revision"]}, 409)
                self.assertTrue(stale["stale"])
                tag = post("/api/reviews", {"action": "tag", "slug": "linked", "color": "#000000",
                                            "hashes": [request[1]["events"][0]["record_sha256"]]})
                refreshed = post("/api/ssm-log", both)
                self.assertEqual(refreshed["revision"], tag["log_revision"])
                self.assertNotEqual(refreshed["revision"], first["revision"])
                pages = refreshed["data"] + post("/api/ssm-log", {**both, "page": 2, "revision": refreshed["revision"]})["data"] \
                    + post("/api/ssm-log", {**both, "page": 3, "revision": refreshed["revision"]})["data"]
                self.assertEqual(len({e["entry_id"] for e in pages}), 229)
                self.assertEqual([e["entry_id"] for e in second["data"]], [e["entry_id"] for e in pages[100:200]])
                # Raw-only and empty searches are not invalidated by review changes.
                raw = {"search": "echo request", "search_scope": "raw"}
                raw_first = post("/api/ssm-log", raw)
                self.assertFalse(raw_first["review_dependent"])
                post("/api/ssm-log-review", {"entry_id": request[11]["entry_id"], "text": "x", "tags": [], "finding": "", "updated": None})
                raw_pages = raw_first["data"] + post("/api/ssm-log", {**raw, "page": 2})["data"] + post("/api/ssm-log", {**raw, "page": 3})["data"]
                self.assertEqual(len({e["entry_id"] for e in raw_pages}), 229)
                self.assertEqual(len(post("/api/ssm-log", {"page": 3, "revision": "anything"})["data"]), 31)
                # Time bounds still apply first (start inclusive, end exclusive) with enhanced search.
                self.assertEqual(ids({"search": "interp-unique", "start": "2026-10-24T17:02:30Z", "end": "2026-10-24T17:02:31Z"}),
                                 (1, [request[150]["entry_id"]]))
                self.assertEqual(ids({"search": "interp-unique", "start": "2026-10-24T17:02:31Z"})[0], 0)
                self.assertEqual(ids({"search": "interp-unique", "end": "2026-10-24T17:02:30Z"})[0], 0)

                # Exact lookup ignores search/time selection and returns the latest saved review.
                exact = post("/api/ssm-log", {"entry_id": request[150]["entry_id"]})
                self.assertEqual((exact["total"], exact["data"][0]["review"]["text"]), (1, "Interp-Unique line\nbreak"))
                self.assertEqual(exact["data"][0]["parameters"], request[150]["parameters"])
                for bad in ({"entry_id": "0" * 64}, {"entry_id": 5}, {"entry_id": request[0]["entry_id"], "search": "x"},
                            {"entry_id": request[0]["entry_id"], "page": 1}, {"search_scope": "analyst"}, {"search_scope": None}):
                    post("/api/ssm-log", bad, 400)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                store.reviews.close()
                store.connection.close()

    def test_compact_notes_preserve_full_bodies_and_stale_edit_protection(self):
        hash_ = self.call("/api/events", {})[1]["data"][0]["record_sha256"]
        body = "🦆 synthetic note\n" * 1200 + "ÉVIDENCE needle beyond preview"
        notes = []
        try:
            for i in range(27):
                status, note = self.call("/api/reviews", {"action": "annotate", "body": body + str(i), "hashes": [hash_]})
                self.assertEqual(status, 200)
                notes.append(note)
            seen, page = [], 1
            while page:
                result = self.call("/api/notes", {"search": "évidence", "page": page})[1]
                self.assertLess(len(json.dumps(result).encode()), 30000)
                seen.extend(n["id"] for n in result["data"])
                page = result["next_page"]
            self.assertEqual(seen, [n["id"] for n in reversed(notes)])
            note = notes[0]
            detail = self.call("/api/notes", {"id": note["id"]})[1]["note"]
            self.assertTrue(detail["body_truncated"])
            self.assertEqual(detail["events"], 1)
            first = self.call("/api/notes", {"id": note["id"], "field": "body"})[1]
            self.assertEqual(first["text"], (body + "0")[:2000])
            status, edit = self.call("/api/reviews", {"action": "edit", "id": note["id"],
                "body": "Replacement", "updated": note["updated"]})
            self.assertEqual(status, 200)
            self.assertEqual(self.call("/api/notes", {"id": note["id"], "field": "body", "offset": 1,
                "sha256": first["sha256"]})[0], 409)
            self.assertEqual(self.call("/api/reviews", {"action": "edit", "id": note["id"],
                "body": "Lost update", "updated": note["updated"]})[0], 400)
            self.assertEqual(self.call("/api/events", {"annotation_id": note["id"]})[1]["last_row"], 1)
            notes[0] = {**note, "updated": edit["updated"]}
        finally:
            for note in notes:
                self.call("/api/reviews", {"action": "delete", "id": note["id"], "updated": note["updated"]})

    def test_immutable_exports_preserve_selection_raw_text_and_access_contract(self):
        try:
            selection = {"start": "2026-10-24T17:00:00Z", "end": "2026-10-25T17:00:00Z"}
            status, info = self.call("/api/exports", {"dataset": "events", "selection": selection})
            self.assertEqual(status, 200, info)
            self.assertTrue(info["ready"])
            self.assertEqual(info["rows"], 3)
            self.assertTrue(info["download_url"].startswith(self.url + "/api/exports/"))
            with urlopen(info["download_url"]) as response:
                original = response.read()
            self.assertEqual((len(original), hashlib.sha256(original).hexdigest()), (info["bytes"], info["sha256"]))
            lines = [json.loads(line) for line in original.splitlines()]
            self.assertEqual(lines[0]["selection"], selection)
            self.assertEqual(lines[0]["evidence"]["records"], 5)
            self.assertEqual({r["id"] for r in lines[1:]}, {2, 3, 4})
            for row in lines[1:]:
                self.assertEqual(row["raw_json"], self.call(f'/api/events/{row["id"]}')[1]["raw_json"])
                self.assertIn("9007199254740993", row["raw_json"])
            row = lines[1]
            self.call("/api/reviews", {"action": "tag", "slug": "export-snapshot", "hashes": [row["record_sha256"]], "color": "#112233"})
            try:
                with urlopen(info["download_url"]) as response:
                    self.assertEqual(response.read(), original)
                self.assertNotEqual(lines[0]["annotation_revision"], self.store.annotation_revision)
            finally:
                self.call("/api/reviews", {"action": "untag", "slug": "export-snapshot", "hashes": [row["record_sha256"]]})
            path = "/api/exports/" + info["id"]
            for headers in ({"Host": "attacker.invalid"}, {"Origin": "https://attacker.invalid"}):
                self.assertEqual(self.call(path, headers=headers)[0], 403)
            for bad in ("../events.duckdb", "0" * 32, "invalid"):
                self.assertEqual(self.call("/api/exports/" + bad)[0], 404)
            self.assertEqual(self.call("/api/exports", {"dataset": "events", "selection": {"sql": "select 1"}})[0], 400)
            self.assertEqual(self.call("/api/exports", {"dataset": "events", "fields": ["raw_event; DROP TABLE events"]})[0], 400)
            with patch("kamotrace.exports.time.time", return_value=2000000000):
                self.assertEqual(self.call(path)[0], 404)
            self.assertFalse(list(self.store.exports.root.iterdir()))
            with patch("kamotrace.exports.MAX_BYTES", 100):
                self.assertEqual(self.call("/api/exports", {"dataset": "events"})[0], 400)
            with patch("kamotrace.exports.MAX_ROWS", 2):
                self.assertEqual(self.call("/api/exports", {"dataset": "events"})[0], 400)
            self.assertFalse(list(self.store.exports.root.iterdir()))
            with patch("kamotrace.exports.MAX_ARTIFACTS", 0):
                self.assertEqual(self.call("/api/exports", {"dataset": "events"})[0], 400)
            entered, release, written = threading.Event(), threading.Event(), threading.Event()
            ordinary_query, prepared = self.store.query, []
            def paused_query(body, **options):
                entered.set()
                if not release.wait(10):
                    raise ValueError("Test export barrier timed out")
                return ordinary_query(body, **options)
            def edit():
                self.call("/api/reviews", {"action": "tag", "slug": "export-snapshot",
                    "hashes": [row["record_sha256"]], "color": "#112233"})
                written.set()
            with patch.object(self.store, "query", side_effect=paused_query):
                exporting = threading.Thread(target=lambda: prepared.append(self.call("/api/exports",
                    {"dataset": "events", "fields": ["id", "tags"]})))
                exporting.start()
                self.assertTrue(entered.wait(10))
                editing = threading.Thread(target=edit)
                editing.start()
                try:
                    self.assertFalse(written.wait(.1))
                finally:
                    release.set()
                    exporting.join(10)
                    editing.join(10)
            self.assertTrue(written.is_set())
            self.assertEqual(prepared[0][0], 200, prepared)
            with urlopen(prepared[0][1]["download_url"]) as response:
                snapshot = [json.loads(line) for line in response.read().splitlines()]
            self.assertFalse(any(t["slug"] == "export-snapshot" for r in snapshot[1:] for t in r["tags"]))
            self.call("/api/reviews", {"action": "untag", "slug": "export-snapshot", "hashes": [row["record_sha256"]]})
            self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), self.before)
        finally:
            if self.store.exports is not None:
                self.store.exports.close()
                self.store.exports = None

    def test_expired_exports_keep_quota_until_all_downloads_close(self):
        from kamotrace.exports import Exports
        exports = Exports()
        def write(emit):
            emit({"type": "manifest"})
            emit({"type": "event", "text": "synthetic" * 1000})
        try:
            with patch("kamotrace.exports.MAX_ARTIFACTS", 1), patch("kamotrace.exports.time.time", return_value=1000) as clock:
                info = exports.prepare(write, self.url)
                with exports.open(info["id"]) as first:
                    with exports.open(info["id"]) as second:
                        # Exception/disconnect paths must also release their lease.
                        with self.assertRaisesRegex(RuntimeError, "disconnect"):
                            with exports.open(info["id"]):
                                raise RuntimeError("disconnect")
                        clock.return_value = 1601
                        with exports.open(info["id"]) as expired:
                            self.assertIsNone(expired)
                        with self.assertRaisesRegex(ValueError, "quota"):
                            exports.prepare(write, self.url)
                        data = first[0].read()
                        self.assertEqual(hashlib.sha256(data).hexdigest(), info["sha256"])
                        self.assertEqual(second[0].read(), data)
                    with self.assertRaisesRegex(ValueError, "quota"):
                        exports.prepare(write, self.url)
                replacement = exports.prepare(write, self.url)
                with exports.open(replacement["id"]) as active:
                    self.assertEqual(active[0].read(), data)
                    exports.close()
                    with exports.open(replacement["id"]) as closed:
                        self.assertIsNone(closed)
                self.assertFalse(exports.root.exists())
        finally:
            exports.close()

    def test_ssm_precise_numeric_identities_keep_missing_and_repeated_ids_distinct(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, database, supplemental = root / "events.json", root / "events.duckdb", root / "ssm.json"
            decimals = ["0.123456789012345678901", "0.123456789012345678902"]
            def record(value, identified):
                event = {"eventTime": "2026-01-02T01:00:00Z", "eventSource": "ssm.amazonaws.com",
                    "eventName": "StartSession", "recipientAccountId": "123", "awsRegion": "us-east-1",
                    "requestParameters": {"target": "i-synthetic", "number": "DECIMAL"},
                    **({"eventID": "repeated-id"} if identified else {})}
                return json.dumps(event).replace('"DECIMAL"', value)
            originals = [record(d, identified) for identified in (False, True) for d in decimals]
            source.write_text('{"Records":[' + ",".join(originals) + "]}")
            # Different key order still deduplicates exact content, preferring original evidence.
            extra = record("0.123456789012345678903", True)
            supplemental.write_text('{"account_id":"123","commands":[],"invocations":[],"invocation_details":[],"cloudtrail_records":['
                + originals[0].replace('{"eventTime": "2026-01-02T01:00:00Z", ', '{')[:-1]
                + ', "eventTime":"2026-01-02T01:00:00Z"},' + extra + "]}")
            build(source, database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            store = Store(database, ssm_export=supplemental)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def post(path, body):
                with urlopen(Request(f"http://127.0.0.1:{server.server_port}" + path,
                    data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                    return json.load(response)
            try:
                entries = post("/api/ssm-log", {})
                self.assertEqual(entries["total"], 5)
                linked = [e["events"][0] for e in entries["data"]]
                self.assertEqual({e["id"] for e in linked if e["id"] is not None}, {1, 2, 3, 4})
                self.assertEqual(sum(e["source"] == "Supplemental SSM export" for e in linked), 1)
                self.assertEqual(len({e["key"] for e in linked}), 5)
                for e in linked:
                    original = post("/api/ssm-event", {"key": e["key"]})
                    expected = originals[e["id"] - 1] if e["id"] else extra
                    value = next(v for v in [*decimals, "0.123456789012345678903"] if v in expected)
                    self.assertIn(value, original["raw_json"])
                    self.assertIn(value, original["request"])
                    if e["id"]:
                        self.assertEqual(hashlib.sha256(original["raw_json"].encode()).hexdigest(), original["record_sha256"])
                exported = post("/api/exports", {"dataset": "ssm", "fields": ["entry_id", "events", "event_raw_json"]})
                with urlopen(exported["download_url"]) as response:
                    data = response.read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), exported["sha256"])
                self.assertEqual({r["events"][0]["key"] for r in map(json.loads, data.splitlines()[1:])}, {e["key"] for e in linked})
                self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                if store.exports is not None:
                    store.exports.close()
                store.reviews.close()
                store.connection.close()

    def test_local_base64_derivations_are_bounded_labelled_and_not_raw(self):
        def encoded(text, encoding="utf-8", urlsafe=False):
            return (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(text.encode(encoding)).decode()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ssm.json"
            document = json.loads(self.ssm_export.read_text())
            wrapped = encoded("wrapped synthetic payload with exact spans")
            nested = encoded("echo " + encoded("nested synthetic payload"))
            document["commands"][0]["record"]["Parameters"] = {"commands": [
                "prefix " + encoded("first synthetic payload") + "; " + encoded("second synthetic payload"),
                wrapped[:20] + "\n" + wrapped[20:], nested,
                encoded("Write-Output 'powershell synthetic'", "utf-16-le"),
                encoded("urlsafe synthetic 😀 >>>", urlsafe=True),
                "a" * 64, "AKIAABCDEFGHIJKLMNOP", "i-0123456789abcdef0", "a-long-ordinary-identifier-1234567890"]}
            document["invocation_details"][0]["record"]["StandardOutputContent"] = encoded("stdout synthetic plaintext")
            document["invocation_details"][0]["record"]["StandardErrorContent"] = encoded("stderr synthetic plaintext")
            path.write_text(json.dumps(document))
            annotations = Path(folder) / "reviews.sqlite3"
            previous = None
            for version in ("local-base64-v1", "synthetic-decoder-v2"):
                with patch("kamotrace.base64_analysis.VERSION", version):
                    store = Store(self.database, annotations=annotations, ssm_export=path)
                server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                def post(route, body):
                    with urlopen(Request(f"http://127.0.0.1:{server.server_port}" + route,
                        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                        return json.load(response)
                try:
                    rows = post("/api/ssm-log", {})["data"]
                    ids = {e["entry_id"] for e in rows}
                    if previous is not None:
                        self.assertEqual(ids, previous)
                    previous = ids
                    alpha = next(e for e in rows if e["instance_id"] == "i-alpha" and e["plugin"] == "shell")
                    derived = alpha["analysis"]["derivations"]
                    texts = {d["text"] for d in derived}
                    self.assertLessEqual({"first synthetic payload", "second synthetic payload", "nested synthetic payload",
                        "wrapped synthetic payload with exact spans", "Write-Output 'powershell synthetic'",
                        "stdout synthetic plaintext", "stderr synthetic plaintext"}, texts)
                    self.assertTrue(any(d["parent"] is not None for d in derived))
                    self.assertTrue(any(d["encoding"] == "utf-16-le" for d in derived))
                    self.assertIn("urlsafe synthetic 😀 >>>", texts)
                    self.assertTrue(any(d["alphabet"] == "urlsafe" for d in derived))
                    self.assertEqual(len(derived), 9)  # Hashes, AWS IDs and ordinary identifiers are not derivations.
                    self.assertEqual(len([d for d in derived if d["source_field"] in ("stdout", "stderr")]), 2)
                    for d in derived:
                        self.assertEqual(d["decoder_version"], version)
                        if d["parent"] is not None:
                            self.assertEqual(derived[d["parent"]]["text"][d["start"]:d["end"]], d["original_text"])
                    for scope, expected in (("raw", 0), ("enhanced", 1)):
                        self.assertEqual(post("/api/ssm-log", {"search": "stdout synthetic plaintext", "search_scope": scope})["total"], expected)
                    self.assertIn("Export derivations", alpha["decoded"])
                    self.assertIn("Local Base64 derivation", alpha["decoded"])
                    content, offset, digest = "", 0, None
                    while offset is not None:
                        chunk = post("/api/ssm-log-text", {"entry_id": alpha["entry_id"], "field": "analysis",
                            "offset": offset, **({"sha256": digest} if digest else {})})
                        content += chunk["text"]
                        offset, digest = chunk["next_offset"], chunk["sha256"]
                    self.assertEqual(json.loads(content), alpha["analysis"])
                    self.assertFalse(alpha["analysis"]["truncated"])
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                    store.connection.close()
                    store.reviews.close()

    def test_base64_analysis_reports_limits_without_unbounded_expansion(self):
        from kamotrace.base64_analysis import Analysis, LIMITS
        def encoded(text):
            return base64.b64encode(text.encode()).decode()
        payload = encoded("bounded synthetic payload")
        cases = [("a" * 65536 + payload, "input_limit"), ("A" * 16385, "candidate_size_limit"),
                 (";".join([payload] * 33), "candidate_limit"),
                 (";".join([encoded("synthetic " * 1100)] * 2), "output_limit"),
                 (encoded("echo " + encoded("echo " + payload)), "depth_limit")]
        for source, reason in cases:
            result = Analysis().analyze([("parameters", source)])
            self.assertTrue(result["truncated"], reason)
            self.assertIn(reason, result["reasons"])
            self.assertLessEqual(result["output_bytes"], 16384)
            self.assertLessEqual(result["candidates"], 32)
        for key, value, reason in (("case_input_code_points", 8, "case_input_limit"),
                ("case_candidates", 0, "case_candidate_limit"), ("case_output_bytes", 0, "case_output_limit"),
                ("case_entries", 0, "case_entry_limit")):
            with patch.dict(LIMITS, {key: value}):
                self.assertIn(reason, Analysis().analyze([("parameters", payload)])["reasons"])
        result = Analysis().analyze([("parameters", [payload] * 513)])
        self.assertIn("source_structure_limit", result["reasons"])

    def test_raw_scalar_paths_share_selection_and_preserve_numeric_text(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            database, source = root / "events.duckdb", root / "events.json"
            stamps = ["00:59:59", "01:00:00", "01:00:01", "01:59:59", "02:00:00", "02:00:01"]
            events = [{"eventID": f"raw-{i}", "eventTime": "2026-01-02T" + stamp + "Z",
                "eventSource": "ssm.amazonaws.com", "eventName": "GetParameter" if i % 2 else "PutParameter",
                "requestParameters": {"name": "/doc", "number": 2 if i == 1 else 10 if i == 3 else 9007199254740993,
                    "fraction": "DECIMAL", "null": None, "array": ["first", "second"], "empty": "", "flag": i % 2 == 0},
                **({"errorCode": "AccessDenied"} if i in (0, 2, 4) else {})} for i, stamp in enumerate(stamps)]
            source.write_text(json.dumps({"Records": events}).replace('"DECIMAL"', '0.123456789012345678901234567890'))
            build(source, database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            store = Store(database)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def post(route, body, status=200):
                try:
                    with urlopen(Request(f"http://127.0.0.1:{server.server_port}" + route,
                        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                        self.assertEqual(response.status, status)
                        return json.load(response)
                except HTTPError as error:
                    self.assertEqual(error.code, status)
                    return json.load(error)
            try:
                fields = ["raw.requestParameters." + k for k in ("name", "number", "fraction", "null", "array", "array[1]", "absent", "empty", "flag")]
                body = {"raw_fields": fields, "filters": [{"field": fields[0], "op": "eq", "value": "/doc"}],
                    "pipeline": 'event_name = "GetParameter" OR event_name = "PutParameter"', "pipeline_version": 1,
                    "start": "2026-01-02T01:00:00Z", "end": "2026-01-02T02:00:00Z"}
                result = post("/api/events", body)
                self.assertEqual({r["id"] for r in result["data"]}, {2, 3, 4})
                self.assertEqual([r["error_code"] for r in result["data"]], [None, "AccessDenied", None])
                for row in result["data"]:
                    values = row["raw_fields"]
                    self.assertEqual(values[fields[1]]["value"], {2: "2", 3: "9007199254740993", 4: "10"}[row["id"]])
                    self.assertEqual(values[fields[2]]["value"], "0.123456789012345678901234567890")
                    self.assertEqual(values[fields[3]], {"value": None, "json_type": "NULL"})
                    self.assertEqual(values[fields[4]], {"value": None, "json_type": "ARRAY"})
                    self.assertEqual(values[fields[5]], {"value": "second", "json_type": "STRING"})
                    self.assertEqual(values[fields[6]], {"value": None, "json_type": None})
                    self.assertEqual(values[fields[7]], {"value": "", "json_type": "STRING"})
                    self.assertEqual(values[fields[8]], {"value": "true" if row["id"] == 3 else "false", "json_type": "BOOLEAN"})
                self.assertNotIn("requestParameters.name", result["sql"])
                self.assertIn("raw.requestParameters.name", result["params"])
                self.assertEqual(post("/api/histogram", body)["total"], 3)
                self.assertEqual([r["id"] for r in post("/api/events", {**body,
                    "sorters": [{"field": fields[1], "dir": "asc"}]})["data"]], [4, 2, 3])
                for field in fields[3:5] + [fields[6]]:
                    self.assertEqual(post("/api/events", {**body, "filters": [{"field": field, "op": "missing"}]})["last_row"], 3)
                self.assertEqual(post("/api/events", {**body, "filters": [{"field": fields[7], "op": "missing"}]})["last_row"], 0)
                self.assertEqual(post("/api/events", {**body, "filters": [{"field": fields[7], "op": "empty"}]})["last_row"], 3)
                summary = post("/api/column-values", {**body, "field": "error_code"})
                self.assertEqual(summary["top"], [{"value": None, "events": 2}, {"value": "AccessDenied", "events": 1}])
                self.assertEqual(post("/api/column-values", {**body, "field": fields[0], "value": "/doc"}), {"total": 3, "events": 3})
                self.assertEqual(post("/api/column-values", {**body, "field": fields[1]})["top"],
                    [{"value": v, "events": 1} for v in ("10", "2", "9007199254740993")])
                failed = {**body, "filters": [*body["filters"], {"field": "raw.errorCode", "op": "not_missing"}]}
                self.assertEqual([r["id"] for r in post("/api/events", failed)["data"]], [3])
                self.assertEqual(post("/api/histogram", failed)["total"], 1)
                exported = post("/api/exports", {"dataset": "events", "selection": failed, "fields": ["id", "raw_fields"]})
                with urlopen(exported["download_url"]) as response:
                    exported_rows = [json.loads(line) for line in response.read().splitlines()]
                self.assertEqual([r["id"] for r in exported_rows[1:]], [3])
                self.assertEqual(exported_rows[1]["raw_fields"][fields[1]]["value"], "9007199254740993")
                post("/api/events", {"raw_fields": ["raw." + "x" * 252, "raw." + ".".join(["a"] * 8), "raw.x[1000]"]})
                post("/api/events", {"raw_fields": ["raw.x" + str(i) for i in range(10)]})
                bad_paths = ["raw.requestParameters.*", "raw.requestParameters.name'); DROP TABLE events;--",
                    "raw.x[-1]", "raw.x[1001]", "raw.x[01]", "raw." + "a." * 8 + "b", "raw." + "x" * 253,
                    'raw["requestParameters"]', "$.requestParameters.name"]
                for path in bad_paths:
                    for route, query in (("/api/events", {"raw_fields": [path]}),
                        ("/api/events", {"filters": [{"field": path, "op": "eq", "value": "x"}]}),
                        ("/api/column-values", {"field": path})):
                        post(route, query, 400)
                post("/api/events", {"raw_fields": ["raw.x" + str(i) for i in range(11)]}, 400)
                post("/api/events", {"raw_fields": ["raw.x" + str(i) for i in range(10)],
                    "filters": [{"field": "raw.y", "op": "missing"}]}, 400)
                self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                if store.exports is not None:
                    store.exports.close()
                store.connection.close()
                store.reviews.close()

    def test_raw_interactive_budget_rejects_large_values_but_keeps_exact_exports(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as resources:
            root = Path(folder)
            source, database = root / "events.json", root / "events.duckdb"
            long = "Z" * 100000
            values = [long, *["x" * 1500 + str(i) for i in range(25)], "\0" * 4500, "🦆" * 2200]
            records = [{"eventID": f"budget-{i}", "eventTime": "2026-01-02T01:00:00Z",
                "eventSource": "ssm.amazonaws.com", "eventName": "Large" if i == 0 else "Medium" if i <= 25 else "Escaped",
                "requestParameters": {"long": value}} for i, value in enumerate(values)]
            source.write_text(json.dumps({"Records": records}))
            build(source, database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            store = Store(database)
            resources.callback(store.connection.close)
            resources.callback(store.reviews.close)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            base = f"http://127.0.0.1:{server.server_port}"
            resources.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            resources.callback(thread.join)
            resources.callback(server.shutdown)
            server.mcp_request = resources.enter_context(http_transport(base))
            path = "raw.requestParameters.long"
            medium = {"filters": [{"field": "event_name", "op": "eq", "value": "Medium"}]}
            escaped = {"filters": [{"field": "event_name", "op": "eq", "value": "Escaped"}]}
            async def session(transport):
                async with Client(transport) as client:
                    for name, args in (("search_events", {"query": {"raw_fields": [path]}}),
                        ("summarize_field", {"field": path}),
                        ("search_events", {"query": {**medium, "raw_fields": [path]}, "size": 25}),
                        ("search_events", {"query": {**escaped, "raw_fields": [path]}}),
                        ("summarize_field", {"field": path, "query": escaped})):
                        result = await client.call_tool(name, args)
                        self.assertTrue(result.is_error, name)
                        self.assertIn("create_export", result.content[0].text)
                        self.assertLess(len(result.model_dump_json().encode()), 80000)
                    # No truncation of exact predicates, grouping keys or full exported values.
                    exact = {"filters": [{"field": path, "op": "eq", "value": values[25]}]}
                    projected = await client.call_tool("search_events", {"query": {**exact, "raw_fields": [path]}})
                    self.assertFalse(projected.is_error)
                    self.assertEqual(projected.structured_content["total"], 1)
                    self.assertEqual(projected.structured_content["events"][0]["raw_fields"][path]["value"], values[25])
                    self.assertLess(len(projected.model_dump_json().encode()), 80000)
                    summary = await client.call_tool("summarize_field", {"field": path, "query": medium})
                    self.assertFalse(summary.is_error)
                    self.assertEqual((summary.structured_content["total"], summary.structured_content["distinct_values"]), (25, 25))
                    self.assertTrue(all(r["value"] in values[1:] and r["events"] == 1 for r in summary.structured_content["top"]))
                    self.assertLess(len(summary.model_dump_json().encode()), 80000)
                    exported = await client.call_tool("create_export", {"dataset": "events",
                        "query": {"raw_fields": [path]}, "fields": ["id", "raw_fields"]})
                    self.assertFalse(exported.is_error, exported)
                    info = exported.structured_content
                    with urlopen(info["download_url"]) as response:
                        data = response.read()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), info["sha256"])
                    self.assertEqual({r["raw_fields"][path]["value"] for r in map(json.loads, data.splitlines()[1:])}, set(values))
                    store.exports.close()
                    store.exports = None
            try:
                for transport in (base + "/mcp", StdioServerParameters(command=sys.executable,
                    args=["-m", "kamotrace", "mcp", "--url", base])):
                    anyio.run(session, transport)
                self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
            finally:
                if store.exports is not None:
                    store.exports.close()

    def test_ssm_batch_reviews_have_independent_results_and_safe_retries(self):
        rows = self.call("/api/ssm-log", {})[1]["data"]
        ids = [e["entry_id"] for e in rows if e["review"]["updated"] is None][:5]
        initial = self.call("/api/ssm-log", {"search": "stdout", "projection": "summary"})[1]
        def edit(id_, **values):
            return {"entry_id": id_, "updated": None, "text": "synthetic batch\n" * 1000,
                    "tags": ["batch"], "finding": "Synthetic finding", **values}
        items = [edit(ids[0]), edit(ids[1], updated="stale"), edit(ids[2], tags=["bad tag"]),
                 edit("0" * 64), edit(ids[3]), edit(ids[3]), edit(ids[4])]
        try:
            status, result = self.call("/api/ssm-log-batch", {"items": items})
            self.assertEqual(status, 200)
            self.assertEqual([r["status"] for r in result["results"]], ["ok", "stale", "invalid", "missing", "invalid", "invalid", "ok"])
            self.assertLess(len(json.dumps(result).encode()), 3000)
            self.assertNotEqual(result["revision"], initial["revision"])
            self.assertEqual(self.call("/api/ssm-log", {"search": "stdout", "projection": "summary", "page": 2,
                "revision": initial["revision"]})[0], 409)
            for id_ in (ids[0], ids[4]):
                saved = self.call("/api/ssm-log", {"entry_id": id_})[1]["data"][0]["review"]
                self.assertEqual(saved["text"], items[0]["text"])
            for id_ in ids[1:4]:
                self.assertIsNone(self.call("/api/ssm-log", {"entry_id": id_})[1]["data"][0]["review"]["updated"])
            replay = self.call("/api/ssm-log-batch", {"items": [items[0]]})[1]
            self.assertEqual(replay["results"][0]["status"], "stale")
            self.assertEqual(self.call("/api/ssm-log-batch", {"items": [{**items[0], "text": ""}] * 101})[0], 400)
            self.assertEqual(self.call("/api/ssm-log-batch", {}, headers={"Content-Length": "1048577"})[0], 400)
        finally:
            with self.store.lock, self.store.reviews:
                for id_ in (ids[0], ids[4]):
                    self.store.reviews.execute("DELETE FROM ssm_log_reviews WHERE entry_id=?", (id_,))
                    self.store.reviews.execute("DELETE FROM ssm_review_sources WHERE entry_id=?", (id_,))

    def test_ssm_orphan_reviews_are_explicit_bounded_and_complete(self):
        # Large Unicode reviews must not leak into even a zero-match ordinary search.
        ids = [f"orphan-{i:05}" for i in range(2003)]
        text = "synthetic 🦆\n" * 2500
        destinations = []
        with self.store.lock, self.store.reviews:
            self.store.reviews.executemany("INSERT INTO ssm_log_reviews VALUES (?,?,?,?,?)",
                [(id_, text, '["preserved"]', text, "synthetic-stamp") for id_ in ids])
        try:
            status, result = self.call("/api/ssm-log", {"search": "nothing matches synthetic orphan"})
            self.assertEqual(status, 200)
            self.assertEqual(result["total"], 0)
            self.assertEqual(result["unmatched_review_count"], len(ids))
            self.assertLess(len(json.dumps(result, ensure_ascii=False).encode()), 5000)
            seen, page = [], 1
            while page:
                status, result = self.call("/api/ssm-log-orphans", {"page": page})
                self.assertEqual(status, 200)
                self.assertLess(len(json.dumps(result, ensure_ascii=False).encode()), 80000)
                seen.extend(row["entry_id"] for row in result["data"])
                page = result["next_page"]
            self.assertEqual(seen, ids)
            detail = self.call("/api/ssm-log-orphans", {"entry_id": ids[-1]})[1]["review"]
            self.assertEqual((detail["text"], detail["finding"], detail["tags"]), (text, text, ["preserved"]))
            self.assertEqual(self.call("/api/ssm-log-orphans", {"page": 0})[0], 400)

            async def sessions():
                for transport in (self.url + "/mcp", StdioServerParameters(
                        command=sys.executable, args=["-m", "kamotrace", "mcp", "--url", self.url])):
                    async with Client(transport) as client:
                        summary = await client.call_tool("list_ssm_orphan_reviews", {"page": 81})
                        self.assertFalse(summary.is_error)
                        self.assertEqual(len(summary.structured_content["data"]), 3)
                        full = await client.call_tool("get_ssm_orphan_review", {"entry_id": ids[-1]})
                        self.assertFalse(full.is_error)
                        self.assertEqual(full.structured_content["review"]["text_length"], len(text))
                        self.assertLess(len(full.model_dump_json().encode()), 80000)
                        offset, pieces, digest = 0, [], None
                        while offset is not None:
                            chunk = await client.call_tool("read_ssm_log_text", {
                                "entry_id": ids[-1], "field": "review.text", "offset": offset,
                                **({"sha256": digest} if digest else {})})
                            self.assertFalse(chunk.is_error)
                            self.assertLess(len(chunk.model_dump_json().encode()), 80000)
                            data = chunk.structured_content
                            pieces.append(data["text"])
                            offset, digest = data["next_offset"], data["sha256"]
                        self.assertEqual("".join(pieces), text)
                        self.assertEqual(digest, hashlib.sha256(text.encode()).hexdigest())
                        orphan = (await client.call_tool("get_ssm_orphan_review", {"entry_id": ids[-1]})).structured_content
                        self.assertEqual(orphan["association"], "unresolved")
                        current = self.call("/api/ssm-log", {})[1]["data"]
                        target = next(e["entry_id"] for e in current if e["review"]["updated"] is None)
                        arguments = {"entry_id": ids[-1], "destination_entry_id": target,
                            "updated": orphan["review"]["updated"], "reason": "Synthetic explicit analyst mapping"}
                        rejected = await client.call_tool("reattach_ssm_review", arguments)
                        self.assertTrue(rejected.is_error)
                        attached = await client.call_tool("reattach_ssm_review", {**arguments, "analyst_mapping": True})
                        self.assertFalse(attached.is_error)
                        destinations.append(target)
            anyio.run(sessions)
        finally:
            with self.store.lock, self.store.reviews:
                self.store.reviews.executemany("DELETE FROM ssm_log_reviews WHERE entry_id=?", [(id_,) for id_ in ids])
                for id_ in destinations:
                    self.store.reviews.execute("DELETE FROM ssm_log_reviews WHERE entry_id=?", (id_,))
                    self.store.reviews.execute("DELETE FROM ssm_review_sources WHERE entry_id=?", (id_,))
                    self.store.reviews.execute("DELETE FROM ssm_review_reattachments WHERE new_entry_id=?", (id_,))

    def test_ssm_log_review_persistence_and_changed_export_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export, annotations = root / "export.json", root / "reviews.sqlite3"
            document = json.loads(self.ssm_export.read_text())
            document["invocation_details"][0]["record"]["ExecutionStartDateTime"] = "2026-10-24T17:03:00Z"
            # Supplemental activity is independently reviewable even with no evidence hash.
            document["cloudtrail_records"].append({"eventID": "supp-failed", "eventSource": "ssm.amazonaws.com",
                "eventName": "SendCommand", "recipientAccountId": "123", "awsRegion": "us-east-2",
                "errorCode": "AccessDenied", "requestParameters": {"commands": ["echo unexecuted"]}})
            document["cloudtrail_records"].append({"eventID": "supp-invalid-time", "eventSource": "ssm.amazonaws.com",
                "eventName": "StartSession", "eventTime": "invalid timestamp", "recipientAccountId": "123",
                "awsRegion": "us-east-2", "requestParameters": {"target": "i-invalid-time"}})
            session_record = {"SessionId": "port-forward-only", "Target": "i-session", "Status": "Terminated",
                "DocumentName": "AWS-StartPortForwardingSession", "StartDate": "2026-10-24T17:00:00Z",
                "EndDate": "2026-10-24T17:05:00Z"}
            document["sessions"] = [{"region": region, "record": session_record} for region in ("us-east-1", "us-west-2")]
            export.write_text(json.dumps(document))
            old_id = None
            saved = None
            for stage in range(4):
                if stage == 2:
                    document["invocation_details"][0]["record"]["StandardOutputContent"] += " changed\n" + "🦆é\u0001\"\\\n" * 3001
                    export.write_text(json.dumps(document))
                if stage == 3:
                    document["invocation_details"].append(document["invocation_details"][0])
                    export.write_text(json.dumps(document))
                store = Store(self.database, annotations=annotations, ssm_export=export)
                server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def post(path, body):
                    with urlopen(Request(f"http://127.0.0.1:{server.server_port}" + path,
                                         data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                        return json.load(response)

                try:
                    rows = post("/api/ssm-log", {})["data"]
                    output = next(e for e in rows if e["instance_id"] == "i-alpha" and e["plugin"] == "shell")
                    self.assertEqual((output["time_ms"], output["time_basis"]), (1792861380000, "Execution start"))
                    supplemental = next(e for e in rows if e["status"] == "Failed request")
                    sessions = [e for e in rows if e["operation"] == "Session metadata"]
                    self.assertEqual(len(sessions), 2)
                    self.assertNotEqual(sessions[0]["entry_id"], sessions[1]["entry_id"])
                    for entry in sessions:
                        self.assertEqual(json.loads(entry["parameters"]), session_record)
                        self.assertEqual(entry["status"], "Terminated")
                        self.assertIsNone(entry["stdout"])
                        self.assertEqual(entry["events"], [])
                    self.assertIsNone(supplemental["time_ms"])
                    self.assertIsNone(rows[-1]["time_ms"])
                    invalid = next(e for e in rows if e["instance_id"] == "i-invalid-time")
                    self.assertIsNone(invalid["time_ms"])
                    self.assertEqual(post("/api/ssm-log", {"search": "i-invalid-time", "end": "2026-10-26T00:00:00Z"})["total"], 0)
                    self.assertIsNone(supplemental["events"][0]["record_sha256"])
                    if stage == 0:
                        old_id = output["entry_id"]
                        saved = post("/api/ssm-log-review", {"entry_id": old_id, "text": "Keep plaintext", "tags": ["persisted"],
                            "finding": "Source-specific finding", "updated": None})
                        post("/api/ssm-log-review", {"entry_id": supplemental["entry_id"], "text": "Supplemental request", "tags": [],
                            "finding": "Failed request without command ID", "updated": None})
                        # Reproduce a legacy sidecar without inventing metadata for its old hashes.
                        with store.reviews:
                            store.reviews.execute("DELETE FROM ssm_review_sources WHERE entry_id=?", (old_id,))
                    elif stage == 1:
                        self.assertEqual(post("/api/ssm-log", {})["unmatched_review_count"], 0)
                        self.assertEqual(output["entry_id"], old_id)
                        self.assertEqual(output["review"], saved)
                        self.assertEqual(supplemental["review"]["text"], "Supplemental request")
                        metadata = json.loads(post("/api/ssm-log-text", {"entry_id": old_id, "field": "review.source"})["text"])
                        self.assertEqual(metadata["reviewed_content_sha256"], old_id)
                    elif stage == 3:
                        duplicates = [e for e in rows if e["instance_id"] == "i-alpha" and e["plugin"] == "shell"]
                        self.assertEqual(len({e["entry_id"] for e in duplicates}), 2)
                        self.assertEqual([e["review"]["text"] for e in duplicates if e["review"]["updated"]], [saved["text"]])
                        self.assertEqual(post("/api/ssm-log-orphans", {"entry_id": old_id})["association"], "ambiguous")
                    else:
                        self.assertNotEqual(output["entry_id"], old_id)
                        self.assertIsNone(output["review"]["updated"])
                        summary = post("/api/ssm-log", {"entry_id": output["entry_id"], "projection": "summary"})
                        self.assertLess(len(json.dumps(summary).encode()), 24001)
                        self.assertEqual(summary["data"][0]["truncated"]["stdout"]["length"], len(output["stdout"]))
                        offset, pieces, digest = 0, [], None
                        while offset is not None:
                            chunk = post("/api/ssm-log-text", {"entry_id": output["entry_id"], "field": "stdout",
                                "offset": offset, "limit": 1931, **({"sha256": digest} if digest else {})})
                            pieces.append(chunk["text"])
                            offset, digest = chunk["next_offset"], chunk["sha256"]
                        self.assertEqual("".join(pieces), output["stdout"])
                        self.assertEqual(digest, hashlib.sha256(output["stdout"].encode()).hexdigest())
                        with self.assertRaises(HTTPError) as error:
                            post("/api/ssm-log-text", {"entry_id": output["entry_id"], "field": "stdout", "sha256": "stale"})
                        self.assertEqual(error.exception.code, 409)
                        # The old review is reported as unmatched, not inherited; the still-current one is not listed.
                        self.assertEqual(post("/api/ssm-log", {"search": "no such entry"})["unmatched_review_count"], 1)
                        self.assertEqual(post("/api/ssm-log-orphans", {})["data"][0]["entry_id"], old_id)
                        self.assertEqual(post("/api/ssm-log-orphans", {"entry_id": old_id})["review"],
                                         {"entry_id": old_id, **saved})
                        relation = post("/api/ssm-log-orphans", {"entry_id": old_id})
                        self.assertEqual((relation["association"], relation["related_entry_id"]),
                                         ("related_changed_content", output["entry_id"]))
                        reattach = {"entry_id": old_id, "destination_entry_id": output["entry_id"],
                            "updated": saved["updated"], "reason": "Analyst verified changed output"}
                        with self.assertRaises(HTTPError) as error:
                            post("/api/ssm-log-reattach", {**reattach, "updated": "stale"})
                        self.assertEqual(error.exception.code, 409)
                        attached = post("/api/ssm-log-reattach", reattach)
                        self.assertEqual(post("/api/ssm-log", {"entry_id": output["entry_id"]})["data"][0]["review"]["text"], saved["text"])
                        history = json.loads(post("/api/ssm-log-text", {"entry_id": old_id, "field": "review.history"})["text"])
                        self.assertEqual(history[0]["basis"], "exact_semantic_identity")
                        self.assertEqual(json.loads(history[0]["old_review"])["updated"], saved["updated"])
                        with self.assertRaises(HTTPError) as error:
                            post("/api/ssm-log-reattach", {**reattach, "updated": attached["updated"]})
                        self.assertIn("already has a review", json.load(error.exception)["error"])
                        with self.assertRaises(HTTPError) as error:
                            post("/api/ssm-log-review", {"entry_id": old_id})
                        self.assertEqual(error.exception.code, 400)
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()
                    store.reviews.close()
                    store.connection.close()

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
        self.assertEqual(self.call("/api/events", {"filters": [{"field": "event_name", "op": "in",
            "value": ["SendCommand", "StartSession"]}]})[1]["last_row"], 4)
        self.assertEqual(self.call("/api/events", {"filters": [{"field": "event_name", "op": "in",
            "value": ["SendCommand,StartSession"]}]})[1]["last_row"], 0)
        for value in ({}, {"value": None}):
            self.assertEqual(self.call("/api/events", {"filters": [{"field": "document_name", "op": "missing", **value}]})[1]["last_row"], 5)
        for body, message in [
                ({"filters": [{"field": "eventName", "op": "eq"}]}, "eventName"),
                ({"filters": [{"field": "event_name", "op": "regex"}]}, "valid operators"),
                ({"sorters": [{"field": "eventName", "dir": "asc"}]}, "valid sort fields"),
                ({"sorters": [{"field": "event_name", "dir": "up"}]}, "asc, desc")]:
            status, error = self.call("/api/events", body)
            self.assertEqual(status, 400)
            self.assertIn(message, error["error"])
        for body in [{"sorters": [{"field": "time_local;DROP TABLE events", "dir": "asc"}]},
                     {"filters": [{"field": "raw_event", "op": "eq", "value": "x"}]},
                     {"start": "2026-10-25T00:00:00"},
                     {"start": "2026-10-26T00:00:00+07:00", "end": "2026-10-25T00:00:00+07:00"},
                     {"size": 100000}]:
            self.assertEqual(self.call("/api/events", body)[0], 400)
        self.assertEqual(self.call("/api/meta", headers={"Origin": "https://attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/meta", headers={"Host": "attacker.invalid"})[0], 403)

    def test_portal_access_requires_configured_host_and_same_origin(self):
        host = "preview.synthetic.invalid"
        origin = f"https://{host}"
        with patch.dict("os.environ", {"PUBLIC_URL": ""}):
            self.assertEqual(self.call("/api/meta", headers={"Host": host})[0], 403)
        with patch.dict("os.environ", {"PUBLIC_URL": origin}):
            self.assertEqual(self.call("/api/meta", headers={"Host": host})[0], 200)
            status, meta = self.call("/api/meta", {}, {"Host": host, "Origin": origin})
            self.assertEqual(status, 200)
            self.assertEqual(meta["timezone"], "UTC")
            self.assertEqual(self.call("/api/meta")[0], 200)
            for headers in [
                {"Host": host, "Origin": "https://attacker.invalid"},
                {"Host": host, "Origin": f"http://{host}"},
                {"Host": host, "Origin": self.url},
                {"Host": host + ".attacker.invalid", "Origin": origin},
                {"Origin": origin},
                {"Host": "attacker.invalid", "X-Forwarded-Host": host, "X-Forwarded-Proto": "https"},
            ]:
                with self.subTest(headers=headers):
                    self.assertEqual(self.call("/api/meta", {}, headers)[0], 403)

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

    def test_key_events_mark_existing_evidence_and_respect_histogram_scopes(self):
        rows = self.call("/api/events", {})[1]["data"]
        hashes = [r["record_sha256"] for r in rows if r["event_id"] in ("event-0", "event-1", "event-3")]
        try:
            status, result = self.call("/api/reviews", {"action": "tag", "slug": "key-event",
                "color": "#7c3aed", "hashes": hashes})
            self.assertEqual(status, 200, result)
            query = {"timezone": "Asia/Jakarta", "start": "2026-10-24T17:00:00Z",
                "end": "2026-10-25T16:59:59Z", "bucket_minutes": 1440,
                "pipeline_version": 1, "pipeline": 'event_name = "StartSession" OR event_id = "event-0"'}
            status, histogram = self.call("/api/histogram", query)
            self.assertEqual(status, 200, histogram)
            self.assertEqual(histogram["total"], 1)
            self.assertEqual(histogram["data"][0]["key_events"], 1)
            expected_ms = int(datetime(2026, 10, 24, 17, tzinfo=timezone.utc).timestamp() * 1000)
            self.assertEqual(histogram["data"][0]["key_first_ms"], expected_ms)
            self.assertEqual(histogram["data"][0]["key_last_ms"], expected_ms)
            self.assertEqual(histogram["key_positions"], {"positions_ms": [expected_ms], "truncated": False})
            scoped = self.call("/api/histogram", {**query, "tags": ["key-event"] * 20})
            self.assertEqual(scoped[0], 200, scoped[1])
            self.assertEqual(scoped[1]["key_positions"], histogram["key_positions"])
            self.assertEqual(sum(r["key_events"] for r in histogram["overview"]), 3)
            overview = self.call("/api/meta", {"timezone": "Asia/Jakarta"})[1]["histogram"]
            self.assertEqual([r["key_events"] for r in overview], [1, 2, 0])
            self.assertEqual(overview[1]["key_first_ms"], expected_ms)
            self.assertEqual(overview[1]["key_last_ms"], expected_ms + 86399000)
            empty = self.call("/api/histogram", {**query, "search": "not-present"})[1]["data"][0]
            self.assertEqual((empty["key_events"], empty["key_first_ms"], empty["key_last_ms"]), (0, None, None))
            self.assertEqual(self.call("/api/events", {"tags": ["key-event"]})[1]["last_row"], 3)
        finally:
            self.call("/api/reviews", {"action": "untag", "slug": "key-event", "hashes": hashes})
        self.assertEqual(sum(r["key_events"] for r in self.call("/api/meta")[1]["histogram"]), 0)

    def test_histogram_selection_concurrency_and_review_invalidation(self):
        selection = {"search": "sEnDcOmMaNd", "timezone": "Asia/Jakarta"}
        scoped = {**selection, "start": "2026-10-24T16:59:59Z", "end": "2026-10-25T16:59:59Z"}
        queries = [(selection, 3), (scoped, 2), ({"pipeline_version": 1,
            "pipeline": 'search "StartSession" OR search "SendCommand"',
            "start": scoped["start"], "end": scoped["end"]}, 3)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            pending = [(route, expected, pool.submit(self.call, route, body))
                       for body, expected in queries for route in ("/api/events", "/api/histogram")]
            for route, expected, response in pending:
                status, result = response.result()
                self.assertEqual(status, 200, result)
                self.assertEqual(result["last_row" if route == "/api/events" else "total"], expected)
        row = self.call("/api/events", scoped)[1]["data"][0]
        selected = {**scoped, "tags": ["histogram-reuse"]}
        self.assertEqual(self.call("/api/histogram", selected)[1]["total"], 0)
        try:
            status, result = self.call("/api/reviews", {"action": "tag", "slug": "histogram-reuse",
                "color": "#7c3aed", "hashes": [row["record_sha256"]]})
            self.assertEqual(status, 200, result)
            self.assertEqual(self.call("/api/events", selected)[1]["last_row"], 1)
            self.assertEqual(self.call("/api/histogram", selected)[1]["total"], 1)
            # Reuse is independent of pagination and bucket width, not the time/filter scope.
            self.assertEqual(self.call("/api/events", {**selected, "page": 2, "size": 25})[1]["data"], [])
            self.assertEqual(self.call("/api/histogram", {**selected, "bucket_minutes": 60})[1]["total"], 1)
        finally:
            self.call("/api/reviews", {"action": "untag", "slug": "histogram-reuse", "hashes": [row["record_sha256"]]})
        self.assertEqual(self.call("/api/histogram", selected)[1]["total"], 0)

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


class GuardDutyContract(unittest.TestCase):
    def test_guardduty_context_http_mcp_and_evidence_safety(self):
        from kamotrace.cli import main
        from case_fixtures import guardduty as import_findings
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as cleanup:
            root = Path(temporary)
            source, database, findings = root / "events.json", root / "case.duckdb", root / "guardduty.json"
            base = {"eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity", "awsRegion": "us-east-1",
                    "userIdentity": {"accountId": "123456789012", "accessKeyId": "AKIASYNTHETIC", "type": "IAMUser"}}
            records = [{**base, "eventID": str(i), "eventTime": stamp} for i, stamp in enumerate([
                "2026-10-01T00:59:59Z", "2026-10-01T01:00:00Z", "2026-10-01T01:03:00Z", "2026-10-01T02:00:00Z"])]
            for changes in ({"awsRegion": "eu-west-1"}, {"userIdentity": {"accountId": "other", "accessKeyId": "AKIASYNTHETIC"}},
                            {"userIdentity": {"accountId": "123456789012", "accessKeyId": "other"}}):
                records.append({**records[2], **changes, "eventID": str(len(records))})
            source.write_text(json.dumps({"Records": records}))
            build(source, database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            finding = {"Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/synthetic/finding/one",
                "Id": "one", "AccountId": "123456789012", "Region": "us-east-1", "Type": "UnauthorizedAccess:IAMUser/Test",
                "Title": "Synthetic API activity <script>neverRun()</script>", "Severity": 8.9,
                "Resource": {"AccessKeyDetails": {"AccessKeyId": "AKIASYNTHETIC"}},
                "Service": {"EventFirstSeen": "2026-10-01T01:00:00Z", "EventLastSeen": "2026-10-01T02:00:00Z", "Archived": True,
                            "AdditionalInfo": {"Value": "{\"sample\": true}"}},
                "large_number": 9007199254740993}
            unsupported = {**finding, "Arn": finding["Arn"] + "-unsupported", "Id": "unsupported", "Resource": {},
                           "Service": {"EventFirstSeen": "2026-10-01T01:00:00Z", "EventLastSeen": "2026-10-01T01:00:00Z"}}
            findings.write_text(json.dumps({"Findings": [finding, unsupported]}))
            sidecar = database.with_suffix(".guardduty.duckdb")
            import_findings(database, findings, sidecar)
            with duckdb.connect(str(sidecar), read_only=True) as connection:
                self.assertEqual(connection.execute("SELECT raw_finding->>'$.large_number' FROM findings LIMIT 1").fetchone()[0], "9007199254740993")
            with self.assertRaises(FileExistsError):
                import_findings(database, findings, sidecar)
            with self.assertRaises(ValueError):
                import_findings(database, findings, database, replace=True)
            sidecar_hash = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            bad = root / "bad.json"
            for invalid in ({"Findings": [finding], "coverage": {"complete": False}},
                            {"Findings": [{**finding, "Severity": True}]},
                            {"Findings": [{**finding, "Service": {"EventFirstSeen": "2026-10-01T01:00:00"}}]}):
                bad.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    import_findings(database, bad, sidecar, replace=True)
                self.assertEqual(hashlib.sha256(sidecar.read_bytes()).hexdigest(), sidecar_hash)
            other = root / "other.duckdb"
            bad.write_text(json.dumps({"Records": records[:1]}))
            build(bad, other)
            with self.assertRaisesRegex(ValueError, "different evidence"):
                Store(other, guardduty=sidecar)
            store = Store(database)
            cleanup.callback(store.reviews.close)
            cleanup.callback(store.connection.close)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            cleanup.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cleanup.callback(thread.join)
            cleanup.callback(server.shutdown)
            url = f"http://127.0.0.1:{server.server_port}"

            def request(path, body=None):
                with urlopen(Request(url + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})) as response:
                    return json.load(response)

            result = request("/api/detections")
            self.assertIsNone(result["run"])
            self.assertEqual((result["guardduty"]["linked_findings"], result["guardduty"]["unlinked_findings"]), (1, 1))
            self.assertTrue(request("/api/meta")["detections_loaded"])
            rule = result["rules"][0]
            self.assertEqual((rule["events"], rule["level"]), (2, "high"))
            query = {"rules": [rule["rule_id"]]}
            events = request("/api/events", query)
            self.assertEqual({r["event_id"] for r in events["data"]}, {"1", "2"})
            self.assertIn("context (not exact)", events["data"][0]["detections"][0]["title"])
            self.assertEqual(request("/api/events", {"min_level": "critical"})["last_row"], 0)
            timeline_query = {"pipeline_version": 1, "pipeline": 'event_type = "guardduty"'}
            timeline = request("/api/events", timeline_query)
            self.assertEqual(timeline["last_row"], 2)
            self.assertEqual(request("/api/events", {})["last_row"], len(records) + 2)
            by_arn = {row["event_id"]: row for row in timeline["data"]}
            snapshot = request(f'/api/events/{by_arn[finding["Arn"]]["id"]}')
            self.assertEqual(json.loads(snapshot["raw_json"]), finding)
            self.assertEqual(snapshot["guardduty"]["sample_status"], "sample=true")
            self.assertEqual(snapshot["guardduty"]["time_basis"], "Service.EventFirstSeen")
            self.assertEqual(snapshot["event_time_ms"], 1790816400000)
            self.assertEqual(request("/api/events/3")["event_time_ms"], 1790816580000)
            self.assertEqual({row["event_time_ms"] for row in snapshot["related_events"]}, {1790816400000, 1790816580000})
            self.assertEqual(request("/api/events/2")["related_events"][0]["event_time_ms"], 1790816400000)
            self.assertEqual({row["id"] for row in snapshot["related_events"]}, {2, 3})
            self.assertEqual(request("/api/events/2")["related_events"][0]["id"], by_arn[finding["Arn"]]["id"])
            unlinked = request(f'/api/events/{by_arn[unsupported["Arn"]]["id"]}')
            self.assertEqual(unlinked["related_events_total"], 0)
            self.assertEqual(unlinked["guardduty"]["sample_status"], "sample=unknown")
            self.assertEqual(request("/api/histogram", {**timeline_query, "bucket_minutes": 60})["total"], 2)
            self.assertEqual(request("/api/events", {**timeline_query, "pipeline": timeline_query["pipeline"] +
                ' | guardduty_sample = "sample=unknown"'})["last_row"], 1)
            self.assertEqual(request("/api/events", {**timeline_query, "start": "2026-10-01T09:00:00+08:00",
                "end": "2026-10-01T09:00:01+08:00", "timezone": "Asia/Singapore"})["last_row"], 2)
            self.assertEqual(request("/api/events", {**timeline_query, "end": "2026-10-01T01:00:00Z"})["last_row"], 0)
            request("/api/reviews", {"action": "tag", "slug": "snapshot-review", "color": "#123456",
                "hashes": [by_arn[finding["Arn"]]["record_sha256"]]})
            self.assertEqual(request("/api/events", {"tags": ["snapshot-review"]})["last_row"], 1)

            async def mcp_contract():
                async with Client(StdioServerParameters(command=sys.executable,
                    args=["-m", "kamotrace", "mcp", "--url", url])) as client:
                    detections = await client.call_tool("list_detections", {})
                    self.assertEqual(detections.structured_content["guardduty"]["findings"], 2)
                    self.assertEqual(detections.structured_content["rules"][0]["snapshots"][0]["id"], by_arn[finding["Arn"]]["id"])
                    response = await client.call_tool("search_events", {"query": query})
                    self.assertEqual(response.structured_content["total"], 2)
                    event = await client.call_tool("get_event", {"id": events["data"][0]["id"]})
                    self.assertEqual(json.loads(event.structured_content["guardduty_findings"][0]["raw_finding"]), finding)
                    independent = await client.call_tool("search_events", {"query": timeline_query})
                    self.assertEqual(independent.structured_content["total"], 2)
                    standalone = await client.call_tool("get_event", {"id": by_arn[unsupported["Arn"]]["id"]})
                    self.assertTrue(standalone.structured_content["raw_json_matches_hash"])
                    self.assertEqual(standalone.structured_content["event_time_ms"], 1790816400000)
                    self.assertEqual(json.loads(standalone.structured_content["raw_json"]), unsupported)
            anyio.run(mcp_contract)
            # Both sources must coexist without numeric catalog-key collisions or altered rule filters.
            suzaku = root / "suzaku.detections.duckdb"
            from kamotrace.suzaku import evidence_identity
            identity = evidence_identity(store.connection)
            with duckdb.connect(str(suzaku)) as out:
                out.execute("CREATE TABLE suzaku_run(metadata JSON)")
                out.execute("INSERT INTO suzaku_run VALUES (?)", [json.dumps({"schema_version": 1,
                    "evidence_source_sha256": identity[0], "evidence_records": identity[1]})])
                out.execute("""CREATE TABLE detections AS SELECT 2::BIGINT AS source_record,
                    'sigma-test' AS rule_id, 'Synthetic Sigma' AS rule_title, 'low' AS level,
                    1::TINYINT AS level_rank, ['Discovery']::VARCHAR[] AS tactics,
                    ['T1087']::VARCHAR[] AS technique_ids, 'linked' AS link_status""")
            combined = Store(database, detections=suzaku)
            try:
                self.assertEqual({r["rule_id"]: r["events"] for r in combined.detections_list()["rules"]},
                                 {rule["rule_id"]: 2, "sigma-test": 1})
                both = combined.query({"rules": [rule["rule_id"], "sigma-test"]})
                self.assertEqual([row["event_id"] for row in both["data"]], ["1"])
                self.assertEqual(len(both["data"][0]["detections"]), 2)
                self.assertEqual(len(combined.detail(2)["guardduty_findings"]), 1)
            finally:
                combined.connection.close()
                combined.reviews.close()
            # Snapshots are immutable, not ARN upserts: preserve repeats and changed updates.
            point = {**finding, "Service": {"EventFirstSeen": "2026-10-01T09:03:00+08:00",
                "EventLastSeen": "2026-10-01T01:03:00Z", "AdditionalInfo": {"Sample": False}}}
            fallback = {**unsupported, "Resource": None, "Service": {"AdditionalInfo": {"Sample": True, "Value": "{\"sample\":false}"}}, "CreatedAt": "2026-10-01T03:00:00Z",
                        "UpdatedAt": "2026-10-01T04:00:00Z"}
            updated_only = {**unsupported, "Service": {}, "UpdatedAt": "2026-10-01T04:00:00Z"}
            last_only = {**unsupported, "Service": {"EventLastSeen": "2026-10-01T05:00:00Z"}}
            unknown_time = {**unsupported, "Service": {}}
            low = {**finding, "Title": "Earlier low snapshot", "Severity": 2}
            critical = {**finding, "Title": "Later critical snapshot", "Severity": 9.5}
            findings.write_text(json.dumps({"Findings": [finding, finding, point, fallback, updated_only, last_only, unknown_time, low, critical]}))
            import_findings(database, findings, sidecar, replace=True)
            from kamotrace.datasets import read_case
            snapshot_start = read_case(database.with_suffix(".fixture-case.json"))["units"][-1]["raw"]["ranges"][0][0]
            reopened = Store(database)
            try:
                independent = reopened.query(timeline_query)["data"]
                self.assertEqual(len(independent), 9)
                self.assertEqual(len({row["id"] for row in independent}), 9)
                self.assertEqual(len({row["record_sha256"] for row in independent}), 8)
                self.assertEqual(by_arn[finding["Arn"]]["record_sha256"], next(row["record_sha256"] for row in independent if row["id"] == snapshot_start))
                self.assertEqual({r["id"] for r in reopened.detail(snapshot_start)["related_events"]}, {2, 3})
                self.assertEqual(len(reopened.detail(2)["guardduty_findings"]), 4)
                self.assertEqual([json.loads(r["raw_finding"]) for r in reopened.detail(2)["guardduty_findings"]], [finding, finding, low, critical])
                catalog = reopened.detections_list()["rules"][0]
                self.assertEqual((catalog["level"], catalog["events"]), ("critical", 2))
                self.assertEqual({(s["title"].removeprefix("GuardDuty context (not exact): "), s["level"], s["occurrences"], s["events"]) for s in catalog["snapshots"]},
                    {(finding["Title"], "high", 2, 2), (finding["Title"], "high", 1, 0),
                     (low["Title"], "low", 1, 2), (critical["Title"], "critical", 1, 2)})
                for retained in catalog["snapshots"]:
                    self.assertEqual(json.loads(reopened.detail(retained["id"])["raw_json"])["Title"], retained["title"].removeprefix("GuardDuty context (not exact): "))
                self.assertEqual(reopened.query({"tags": ["snapshot-review"]})["last_row"], 2)
                self.assertEqual(reopened.detail(snapshot_start + 2)["tags"], [])
                self.assertEqual(reopened.detail(snapshot_start + 2)["related_events_total"], 0)
                self.assertIn("point observation", reopened.detail(snapshot_start + 2)["guardduty"]["link_status"])
                self.assertEqual(reopened.detail(snapshot_start + 2)["guardduty"]["sample_status"], "sample=false")
                self.assertEqual(reopened.detail(snapshot_start + 3)["guardduty"]["time_basis"], "CreatedAt")
                self.assertEqual(reopened.detail(snapshot_start + 3)["guardduty"]["sample_status"], "sample=unknown")
                self.assertEqual(next(r["time_local"] for r in independent if r["id"] == snapshot_start + 3), "2026-10-01 03:00:00")
                self.assertEqual([reopened.detail(snapshot_start + i - 1)["guardduty"]["time_basis"] for i in (5, 6, 7)],
                                 ["UpdatedAt", "Service.EventLastSeen", "unknown"])
                self.assertIsNone(reopened.detail(snapshot_start + 6)["event_time_ms"])
                self.assertEqual(reopened.query({**timeline_query, "start": "2026-10-01T00:00:00Z"})["last_row"], 8)
            finally:
                reopened.connection.close()
                reopened.reviews.close()
            # Input ordering must not pick the catalog severity or hide a changed title.
            findings.write_text(json.dumps({"Findings": [critical, low]}))
            import_findings(database, findings, sidecar, replace=True)
            reversed_store = Store(database)
            try:
                group = reversed_store.detections_list()["rules"][0]
                self.assertEqual((group["level"], group["events"]), ("critical", 2))
                self.assertEqual({s["level"] for s in group["snapshots"]}, {"low", "critical"})
                self.assertEqual({json.loads(reversed_store.detail(s["id"])["raw_json"])["Title"]
                    for s in group["snapshots"]}, {low["Title"], critical["Title"]})
            finally:
                reversed_store.connection.close()
                reversed_store.reviews.close()
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)


class MFAContract(unittest.TestCase):
    """Current IAM state and historical MFA are separate, exactly linked evidence."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.database = root / "events.duckdb"
        cls.inventory_export = root / "inventory"
        report = inventory_fixture(cls.inventory_export)
        user = report["iam"]["users"][0]
        user["activity"].update(mfa_status="collected", mfa_devices=[{"SerialNumber": "arn:aws:iam::123:mfa/synthetic"}],
                                login_profile_status="collected", login_profile={"PasswordResetRequired": False})
        (cls.inventory_export / "report.json").write_text(json.dumps(report), encoding="utf-8")
        principal = {"type": "IAMUser", "accountId": "123", "arn": user["Arn"], "principalId": user["UserId"]}
        cls.events = []
        for value, result in [("Yes", "Success"), ("Yes", "Success"), ("No", "Success"),
                              (None, "Success"), ("No", "Failure"), ("Yes", "Success")]:
            cls.events.append({"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com", "userIdentity": principal,
                               "responseElements": {"ConsoleLogin": result}, "additionalEventData": {"MFAUsed": value}})
        cls.events[-1]["errorCode"] = "SyntheticDenied"  # Never count errored success-shaped data as authentication.
        for flag in (True, "false", None, "unrecognized"):
            cls.events.append({"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com", "userIdentity": {
                **principal, "sessionContext": {"attributes": {"mfaAuthenticated": flag}}}})
        cls.events.append({"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com", "userIdentity": {
            **principal, "principalId": "AIDOLDRECREATED"}, "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}})
        for name, role_id, flag in (("one", "AROAUDITOR", "true"), ("two", "AROAUDITOR", "false"), ("old", "AROOLD", "true")):
            cls.events.append({"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com", "userIdentity": {
                "type": "AssumedRole", "accountId": "123", "arn": f"arn:aws:sts::123:assumed-role/auditor/{name}", "principalId": f"{role_id}:{name}",
                "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::123:role/team/auditor", "principalId": role_id},
                                   "attributes": {"mfaAuthenticated": flag}}}})
        for index, event in enumerate(cls.events):
            event.update(eventID=f"mfa-{index}", eventTime=f"2026-10-01T00:{index:02}:00Z", awsRegion="us-east-1")
        # A different Region remains a separate group, even for the same user.
        cls.events[1]["awsRegion"] = "eu-west-1"
        source = root / "events.json"
        source.write_text(json.dumps({"Records": cls.events}), encoding="utf-8")
        build(source, cls.database)
        cls.before = hashlib.sha256(cls.database.read_bytes()).hexdigest()
        cls.store = Store(cls.database, inventory_export=cls.inventory_export)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=cls.store))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.store.connection.close()
        cls.store.reviews.close()
        assert hashlib.sha256(cls.database.read_bytes()).hexdigest() == cls.before
        cls.temp.cleanup()

    call = BrowserContract.call

    def test_mfa_history_keeps_unknown_failed_recreated_and_role_sessions_distinct(self):
        spec = {"kind": "identity", "value": "arn:aws:iam::123:user/team/analyst", "account": "123"}
        self.assertIsNone(self.call("/api/reference", {**spec, "include_history": False})[1]["history_coverage"])
        status, card = self.call("/api/reference", spec)
        self.assertEqual(status, 200, card)
        current = next(m for m in card["matches"] if m.get("iam"))
        self.assertEqual(current["iam"]["activity"]["mfa_status"], "collected")
        groups = [m for m in card["matches"] if m["source"] == "cloudtrail"]
        self.assertEqual(len(groups), 2)
        self.assertEqual(sum(m["identity"]["event_count"] for m in groups), 10)
        expected = {"console_success_with_mfa": 2, "console_success_without_mfa": 1,
                    "console_success_mfa_unknown": 1, "console_failed_or_result_unknown": 2,
                    "session_mfa_authenticated": 1, "session_mfa_not_authenticated": 1, "session_mfa_unknown": 2}
        for key, count in expected.items():
            self.assertEqual(sum(m["mfa"][key] for m in groups), count, key)
        _, events = self.call("/api/events", {})
        event_ids = {row["record_sha256"]: row["event_id"] for row in events["data"]}
        sample_ids = dict(zip(expected, ({"mfa-0", "mfa-1"}, {"mfa-2"}, {"mfa-3"}, {"mfa-4", "mfa-5"}, {"mfa-6"}, {"mfa-7"}, {"mfa-8", "mfa-9"})))
        for group in groups:
            for sample in group["mfa"]["samples"]:
                self.assertIn(event_ids[sample["record_sha256"]], sample_ids[sample["category"]])
        self.assertIn("stable principal ID", card["history_association"])
        self.assertEqual(card["history_coverage"]["first_event"], "2026-10-01 00:00:00+00")
        _, scoped = self.call("/api/reference", {**spec, "region": "eu-west-1"})
        self.assertEqual([m["mfa"]["console_success_with_mfa"] for m in scoped["matches"] if m["source"] == "cloudtrail"], [1])
        _, role = self.call("/api/reference", {"kind": "identity", "value": "auditor"})
        sessions = [m for m in role["matches"] if m["source"] == "cloudtrail"]
        self.assertEqual({m["id"].rsplit("/", 1)[-1] for m in sessions}, {"one", "two"})
        self.assertEqual([m["identity"]["event_count"] for m in sessions], [1, 1])
        _, session = self.call("/api/reference", {"kind": "identity", "value": "arn:aws:sts::123:assumed-role/auditor/one"})
        self.assertEqual([m["identity"]["event_count"] for m in session["matches"] if m["source"] == "cloudtrail"], [1])


class CaseManifestContract(unittest.TestCase):
    def test_histogram_preserves_submillisecond_occurrences_and_half_open_buckets(self):
        from kamotrace.datasets import admit
        from kamotrace.event_index import prepare
        # The earliest two occurrences round UP to a millisecond boundary. The
        # other three distinguish exact inclusion, exclusive end and bucket side.
        for edge in ("1970-01-01T00:00:00+00:00", "2026-01-03T16:00:00+00:00"):
            boundary = datetime.fromisoformat(edge)
            stamps = [(boundary + timedelta(microseconds=offset)).isoformat()
                      for offset in (-194, -194, 0, 194, 1001)]
            with tempfile.TemporaryDirectory() as folder, ExitStack() as cleanup:
                root = Path(folder)
                case, source = root / "case.json", root / "events.json"
                source.write_text(json.dumps({"Records": [
                    {"eventID": str(i), "eventTime": stamp, "eventName": "SyntheticFraction"}
                    for i, stamp in enumerate(stamps)]}))
                admit(case, "fractional-acquisition", "cloudtrail", [source])
                prepare(case, ["fractional-acquisition"])
                store = Store(case=case)
                cleanup.callback(store.selection_directory.cleanup)
                cleanup.callback(store.connection.close)
                cleanup.callback(store.reviews.close)
                server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                cleanup.callback(server.server_close)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                cleanup.callback(worker.join)
                cleanup.callback(server.shutdown)
                self.url = f"http://127.0.0.1:{server.server_port}"
                server.mcp_request = cleanup.enter_context(http_transport(self.url))

                for zone in ("UTC", "Asia/Singapore"):
                    queries = [
                        ({"bucket_minutes": 525600}, 5, None),
                        # Singapore was UTC+07:30 at the epoch: half-hour
                        # boundaries discriminate bucket sides in both eras/zones.
                        ({"bucket_minutes": 30}, 5, [2, 3]),
                        ({"bucket_minutes": 30, "start": stamps[0], "end": edge}, 2, [2]),
                        ({"bucket_minutes": 30, "start": edge, "end": stamps[3]}, 1, [1]),
                        ({"bucket_minutes": 30, "start": stamps[3], "end": stamps[4]}, 1, [1]),
                    ]
                    for query, expected, buckets in queries:
                        with self.subTest(transport="http", edge=edge, zone=zone, query=query):
                            body = {"timezone": zone, **query}
                            status, events = BrowserContract.call(self, "/api/events", body)
                            self.assertEqual(status, 200, events)
                            self.assertEqual(events["last_row"], expected)
                            status, histogram = BrowserContract.call(self, "/api/histogram", body)
                            self.assertEqual(status, 200, histogram)
                            self.assertEqual(histogram["total"], expected)
                            if buckets is not None:
                                self.assertEqual([r["events"] for r in histogram["data"]], buckets)

                    async def session():
                        async with Client(self.url + "/mcp") as client:
                            for query, expected, buckets in queries:
                                with self.subTest(transport="mcp", edge=edge, zone=zone, query=query):
                                    result = await client.call_tool("event_histogram", {
                                        "bucket_minutes": query["bucket_minutes"], "query": {"timezone": zone,
                                            **{k: v for k, v in query.items() if k != "bucket_minutes"}}})
                                    self.assertFalse(result.is_error, result)
                                    histogram = result.structured_content
                                    self.assertEqual(histogram["total"], expected)
                                    if buckets is not None:
                                        self.assertEqual([r["events"] for r in histogram["buckets"]], buckets)
                    anyio.run(session)

    def test_sparse_case_ssm_occurrences_and_manual_edits_through_http_and_mcp(self):
        from kamotrace.datasets import admit
        from kamotrace.event_index import prepare
        from kamotrace.other_events import MANUAL_BASE
        with tempfile.TemporaryDirectory() as folder, ExitStack() as cleanup:
            root = Path(folder)
            case, source, export = root / "case.json", root / "aws.json", root / "ssm.json"
            event = {"eventID": "duplicate-occurrence", "eventTime": "2026-10-25T00:00:00Z",
                "eventName": "SendCommand", "eventSource": "ssm.amazonaws.com",
                "recipientAccountId": "123", "awsRegion": "us-east-1",
                "responseElements": {"command": {"commandId": "exact-command"}},
                "requestParameters": {"number": 9007199254740993}}
            source.write_text(json.dumps({"Records": [event, event,
                {**event, "eventID": "unprepared"}, {**event, "recipientAccountId": "456"}]}))
            admit(case, "excluded-acquisition", "cloudtrail", [source])
            unit = admit(case, "selected-acquisition", "cloudtrail", [source])
            first = unit["raw"]["ranges"][0][0]
            self.assertGreater(first, 4)
            prepare(case, ["selected-acquisition"], [[first, first + 2]])
            command = {"CommandId": "exact-command", "RequestedDateTime": "2026-10-25T00:00:00Z",
                       "InstanceIds": ["i-alpha", "i-beta"], "Parameters": {"commands": ["synthetic only"]}}
            export.write_text(json.dumps({"account_id": "123",
                "commands": [{"region": region, "record": command} for region in ("us-east-1", "eu-west-1")],
                "invocations": [{"region": "us-east-1", "record": {"CommandId": "exact-command",
                    "InstanceId": "i-beta", "CommandPlugins": [{"Name": "combined", "Output": "combined only"}]}}],
                "invocation_details": [{"region": "us-east-1", "record": {"CommandId": "exact-command",
                    "InstanceId": "i-alpha", "PluginName": plugin, "StandardOutputContent": stdout,
                    "StandardErrorContent": stderr}} for plugin, stdout, stderr in
                    [("first", "alpha output", ""), ("second", "", "alpha error")]],
                "cloudtrail_records": [event]}))
            store = Store(case=case, units=["selected-acquisition"], ssm_export=export)
            cleanup.callback(store.selection_directory.cleanup)
            cleanup.callback(store.connection.close)
            cleanup.callback(store.reviews.close)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            cleanup.callback(server.server_close)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cleanup.callback(worker.join)
            cleanup.callback(server.shutdown)
            self.url = f"http://127.0.0.1:{server.server_port}"
            server.mcp_request = cleanup.enter_context(http_transport(self.url))

            def rest(route, body=None, status=200):
                code, value = BrowserContract.call(self, route, body)
                self.assertEqual(code, status, value)
                return value

            key = '["123","us-east-1","exact-command"]'
            linked = rest("/api/events", {"command_key": key})
            self.assertEqual({row["id"] for row in linked["data"]}, {first, first + 1})
            self.assertEqual(rest("/api/histogram", {"command_key": key})["total"], 2)
            detail = rest("/api/ssm-detail", {"key": key})
            self.assertEqual({row["id"] for row in detail["events"]}, {first, first + 1})
            self.assertEqual(len(detail["events"]), 2)  # Supplemental copy adds no occurrence.
            systems = {row["instance_id"]: row for row in detail["systems"]}
            self.assertEqual([row["PluginName"] for row in systems["i-alpha"]["details"]], ["first", "second"])
            self.assertEqual(systems["i-beta"]["details"], [])
            self.assertEqual(systems["i-beta"]["invocation"]["CommandPlugins"][0]["Output"], "combined only")
            self.assertEqual(rest("/api/ssm-detail", {"key": '["123","eu-west-1","exact-command"]'})["events"], [])
            self.assertEqual(rest(f"/api/events/{first}")["ssm_commands"], [{"key": key, "command_id": "exact-command"}])
            self.assertEqual(rest(f"/api/events/{first + 1}")["ssm_commands"], [{"key": key, "command_id": "exact-command"}])
            rest(f"/api/events/{first + 2}", status=404)
            rest("/api/events/1", status=404)
            raw = '{"date":"2026-10-25T00:00:00Z","content":{"amount":9007199254740993}}'

            async def session():
                async with Client(self.url + "/mcp") as client:
                    result = (await client.call_tool("get_ssm_command", {"key": key})).structured_content
                    self.assertEqual({row["id"] for row in result["events"]}, {first, first + 1})
                    created = await client.call_tool("create_manual_event", {"record_json": raw, "origin": "Synthetic review"})
                    self.assertFalse(created.is_error, created)
                    value = created.structured_content
                    self.assertGreater(value["id"], MANUAL_BASE)
                    changed = {**value, "record_json": raw.replace("amount", "corrected_amount"), "origin": "Synthetic correction"}
                    changed.pop("record_sha256")
                    edited = await client.call_tool("edit_manual_event", changed)
                    self.assertFalse(edited.is_error, edited)
                    self.assertEqual(edited.structured_content["id"], value["id"])
                    stale = await client.call_tool("edit_manual_event", changed)
                    self.assertTrue(stale.is_error)
                    event_detail = (await client.call_tool("get_event", {"id": value["id"]})).structured_content
                    self.assertIn("9007199254740993", event_detail["raw_json"])
                    rest("/api/manual-events", {**changed, "id": first}, status=400)
                    return value["id"]
            manual_id = anyio.run(session)
            self.assertEqual(rest("/api/events", {})["last_row"], 3)
            cleanup.close()
            # The same stable case owns manual state across selection changes/reopen.
            reopened = Store(case=case, units=["selected-acquisition"], ssm_export=export)
            try:
                self.assertIn("corrected_amount", reopened.detail(manual_id)["raw_json"])
                self.assertEqual(reopened.meta["total"], 3)
                self.assertEqual(reopened.coverage["excluded_units"], ["excluded-acquisition"])
            finally:
                reopened.connection.close()
                reopened.reviews.close()
                reopened.selection_directory.cleanup()
            # Test-only deletion exercises durable high-water state, not a delete API.
            manual_path = case.with_suffix(".manual.duckdb")
            with duckdb.connect(str(manual_path)) as connection:
                connection.execute("DELETE FROM raw_events")
                connection.execute("DELETE FROM revisions")
            from kamotrace.other_events import save_manual
            identity = [store.case_manifest["case_id"]]
            replacement = save_manual(manual_path, identity, {"record_json": raw, "origin": "Synthetic replacement"})
            self.assertEqual(replacement[0], manual_id + 1)
            with duckdb.connect(str(manual_path)) as connection:
                connection.execute("UPDATE manual_ids SET next_record=?", [2 ** 53 - 1])
            last = save_manual(manual_path, identity, {"record_json": raw, "origin": "Synthetic last exact ID"})
            self.assertEqual(last[0], 2 ** 53 - 1)
            from kamotrace.importer import sha256
            before = sha256(manual_path)
            with self.assertRaisesRegex(ValueError, "namespace exhausted"):
                save_manual(manual_path, identity, {"record_json": raw, "origin": "Synthetic overflow"})
            self.assertEqual(sha256(manual_path), before)

    def test_guardduty_snapshot_ids_and_links_use_declared_case_coverage(self):
        from kamotrace.cli import main
        from kamotrace.datasets import admit, read_case
        from kamotrace.event_index import prepare
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source, findings = root / "case.json", root / "aws.json", root / "findings.json"
            source.write_text(json.dumps({"Records": [
                {"eventID": "event-" + str(i), "eventTime": f"2026-10-25T00:00:0{i}Z",
                 "eventName": "SendCommand", "awsRegion": "us-east-1",
                 "userIdentity": {"accountId": "123", "accessKeyId": "SYNTHETIC"}} for i in range(3)]}))
            admit(case, "AWS", "cloudtrail", [source])
            prepare(case, ["AWS"], [[1, 3]])
            finding = {"Arn": "arn:aws:guardduty:us-east-1:123:detector/synthetic/finding/one", "Id": "one",
                "AccountId": "123", "Region": "us-east-1", "Type": "Synthetic", "Severity": 7,
                "Service": {"EventFirstSeen": "2026-10-25T00:00:01Z", "EventLastSeen": "2026-10-25T00:00:02Z"},
                "Resource": {"AccessKeyDetails": {"AccessKeyId": "SYNTHETIC"}}, "large": 9007199254740993}
            findings.write_text(json.dumps({"Findings": [finding, finding]}))
            self.assertEqual(main(["guardduty", "--case", str(case), "--snapshot-unit", "alerts-1",
                                  "--findings", str(findings)]), 0)
            before = read_case(case)
            records = before["units"][1]["raw"]["ranges"][0][0]
            self.assertGreater(records, 3)
            store = Store(case=case)
            try:
                self.assertEqual(store.meta["total"], 4)
                snapshots = store.query({"filters": [{"field": "event_type", "op": "eq", "value": "guardduty"}]})["data"]
                self.assertEqual({r["id"] for r in snapshots}, {records, records + 1})
                self.assertEqual(len({r["record_sha256"] for r in snapshots}), 1)
                for row in snapshots:
                    detail = store.detail(row["id"])
                    self.assertIn("9007199254740993", detail["raw_json"])
                    self.assertEqual([e["id"] for e in detail["related_events"]], [2])
                self.assertEqual({e["id"] for e in store.detail(2)["related_events"]}, {records, records + 1})
                self.assertEqual(store.detail(1)["related_events"], [])
                self.assertIsNone(store.detail(3))
            finally:
                store.connection.close()
                store.reviews.close()
                store.selection_directory.cleanup()
            # A repeated acquisition is reused; rebuilding links cannot reissue snapshot IDs.
            self.assertEqual(main(["guardduty", "--case", str(case), "--snapshot-unit", "alerts-1",
                                  "--findings", str(findings), "--replace"]), 0)
            self.assertEqual(read_case(case), before)

    def test_case_sidecars_and_saved_queries_bind_exact_selected_coverage(self):
        from kamotrace.cli import main
        from kamotrace.datasets import admit
        from kamotrace.event_index import prepare
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source, geo = root / "case.json", root / "aws.json", root / "geo.jsonl"
            source.write_text(json.dumps({"Records": [
                {"eventID": f"event-{i}", "eventTime": f"2026-10-25T00:00:0{i}Z",
                 "eventName": "SendCommand", "awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.1"}
                for i in range(2)]}))
            geo.write_text(json.dumps({"ip": "192.0.2.1", "country": "Synthetic country"}) + "\n")
            admit(case, "A", "cloudtrail", [source])
            prepare(case, ["A"], [[1, 2]])
            timeline = root / "timeline.duckdb"
            with duckdb.connect(str(timeline)) as connection:
                connection.execute('''CREATE TABLE timeline("Timestamp" TIMESTAMP, RuleTitle VARCHAR,
                    "Level" VARCHAR, EventName VARCHAR, AwsRegion VARCHAR, EventID VARCHAR, RuleAuthor VARCHAR,
                    Tactics VARCHAR[], TechniqueIDs VARCHAR[], OtherTags VARCHAR[], RuleID VARCHAR);
                    CREATE TABLE suzaku_meta(schema_version INTEGER, suzaku_version VARCHAR, command VARCHAR,
                    timestamp_tz VARCHAR, rules_version VARCHAR, rules_count BIGINT);
                    INSERT INTO suzaku_meta VALUES (1, '3.0.0', 'aws-ct-timeline', 'UTC', 'synthetic', 1);
                    INSERT INTO timeline VALUES ('2026-10-25 00:00:00', 'Synthetic rule', 'high',
                        'SendCommand', 'us-east-1', 'event-0', 'synthetic', [], [], [], 'synthetic-rule'),
                        ('2026-10-25 00:00:01', 'Synthetic rule', 'high',
                        'SendCommand', 'us-east-1', 'event-1', 'synthetic', [], [], [], 'synthetic-rule')''')
            self.assertIn(main(["enrich", "--case", str(case), "--unit", "A", "--jsonl", str(geo)]), (None, 0))
            self.assertIn(main(["suzaku", "--case", str(case), "--unit", "A", "--timeline", str(timeline)]), (None, 0))
            store = Store(case=case)
            try:
                row = store.query({})["data"][0]
                self.assertEqual(row["country"], "Synthetic country")
                self.assertEqual([d["rule_id"] for d in row["detections"]], ["synthetic-rule"])
                store.review_write({"action": "annotate", "body": "Synthetic finding",
                    "hashes": [row["record_sha256"]], "context": {"search": "SendCommand"}})
                context = json.loads(store.reviews.execute("SELECT context FROM annotations").fetchone()[0])
                self.assertEqual(store.query(context)["last_row"], 1)
            finally:
                store.connection.close()
                store.reviews.close()
                store.selection_directory.cleanup()
            prepare(case, ["A"])
            # Old sidecars cannot silently answer a newly widened selection.
            with self.assertRaisesRegex(ValueError, "different evidence"):
                Store(case=case)
            # Explicit fresh sidecar paths preserve the independent Findings store.
            empty_enrichment = root / "new.enrichment.duckdb"
            self.assertIn(main(["enrich", "--case", str(case), "--jsonl", str(geo),
                                  "--output", str(empty_enrichment)]), (None, 0))
            self.assertIn(main(["suzaku", "--case", str(case), "--timeline", str(timeline),
                                  "--replace"]), (None, 0))
            store = Store(case=case, enrichment=empty_enrichment)
            try:
                self.assertEqual(store.query({})["last_row"], 2)
                with self.assertRaisesRegex(ValueError, "different case/coverage"):
                    store.query(context)
                with self.assertRaisesRegex(ValueError, "different case/coverage"):
                    store.histogram(context)
            finally:
                store.connection.close()
                store.reviews.close()
                store.selection_directory.cleanup()

    def test_uac_raw_admission_keeps_envelope_precision_and_occurrences(self):
        from kamotrace.cli import main
        from kamotrace.datasets import read_case
        from kamotrace.importer import sha256
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "parse-only"
            source.mkdir()
            observation = {"ecs": {"version": "8.17.0"}, "@timestamp": "2021-03-08T01:02:00Z",
                "event": {"id": "emission-one", "module": "tracequarry"}, "message": "synthetic session",
                "host": {"id": "host-A", "ip": ["192.0.2.1", "192.0.2.1"]},
                "uac": {"profile_version": "1.1.0", "run_id": "run-one", "collection": {"id": "collection-one"},
                    "identity": {"policy": "source-emission-v1", "emission_id": "emission-one"}, "source_refs": [],
                    "time": {"policy": "claim-time-v1", "selected": "source", "basis": "event_time",
                             "candidates": [{"id": "source", "value": "2021-03-08T01:02:00Z"}]}},
                "large": 9007199254740993}
            text = json.dumps(observation)
            (source / "observations.jsonl").write_text(text + "\n" + text + "\n")
            (source / "source_index.json").write_text(json.dumps({"analysis": {"status": "not_run"},
                "sources": [{"status": "partial", "uninterpreted_lines": 7}]}))
            manifest = {"mode": "parse_only", "status": "complete", "ecs_version": "8.17.0", "uac_profile_version": "1.1.0",
                "time_policy": "claim-time-v1", "identity_policy": "source-emission-v1", "deduplication": "none",
                "run_id": "run-one", "collection_id": "collection-one", "input_verification": "hash_size_mtime_verified",
                "analysis": {"status": "not_run"}, "coverage": {"events": 2, "sources_partial": 1}, "outputs": []}
            for name in ("observations.jsonl", "source_index.json"):
                file = source / name
                manifest["outputs"].append({"name": name, "size": file.stat().st_size, "sha256": sha256(file)})
            (source / "run_manifest.json").write_text(json.dumps(manifest))
            case = root / "case.json"
            from kamotrace.datasets import admit
            with self.assertRaisesRegex(ValueError, "one completed parse-only export"):
                admit(case, "ambiguous", "uac", [source, source])
            self.assertFalse(case.exists())
            args = ["auto", "--case", str(case), "--unit", "host-A/acquisition-1", "--kind", "uac",
                    "--source", str(source), "--no-serve"]
            self.assertEqual(main(args), 0)
            before = read_case(case)
            self.assertEqual(main(args), 0)
            self.assertEqual(read_case(case), before)
            with duckdb.connect(before["units"][0]["raw"]["path"], read_only=True) as connection:
                rows = connection.execute("SELECT source_record, record_sha256, raw_event FROM raw_events ORDER BY source_record").fetchall()
                self.assertEqual([r[0] for r in rows], [1, 2])
                self.assertNotEqual(rows[0][1], rows[1][1])
                self.assertEqual([r[2] for r in rows], [text, text])
                self.assertEqual(connection.execute("SELECT count(*) FROM uac_ip_attributes").fetchone()[0], 4)
            from kamotrace.event_index import prepare
            second = admit(case, "host-A/acquisition-2", "uac", [source])
            second_first = second["raw"]["ranges"][0][0]
            prepare(case, ["host-A/acquisition-1"], [[1, 2]])
            prepare(case, ["host-A/acquisition-2"])
            for key, count, sample in (("host-A/acquisition-1", 1, 1), ("host-A/acquisition-2", 2, second_first)):
                store = Store(case=case, units=[key])
                try:
                    context = store.computers({"unit_id": key})
                    self.assertEqual((context["unit_id"], context["records"], context["scanned"]), (key, count, count))
                    self.assertEqual(context["imports"][0]["records"], count)
                    self.assertFalse(context["truncated"])
                    self.assertEqual(context["cards"][0]["sample_record"], sample)
                    self.assertEqual(json.loads(store.detail(sample)["raw_json"])["host"]["id"], "host-A")
                    with self.assertRaisesRegex(ValueError, "stable unit_id"):
                        store.computers({"dataset_index": 0})
                    with self.assertRaisesRegex(ValueError, "selected prepared UAC unit"):
                        store.computers({"unit_id": "excluded-acquisition"})
                finally:
                    store.connection.close()
                    store.reviews.close()
                    store.selection_directory.cleanup()
            completed = read_case(case)
            manifest["coverage"]["events"] = 3
            (source / "run_manifest.json").write_text(json.dumps(manifest))
            self.assertNotEqual(main([*args[:4], "host-A/acquisition-3", *args[5:]]), 0)
            failed = read_case(case)
            self.assertEqual(failed["units"], completed["units"])
            # Validation fails after insertion, so its issued block stays burned.
            self.assertGreater(failed["next_record"], completed["next_record"])

    def test_viewer_attaches_declared_coverage_without_preparing(self):
        from kamotrace.datasets import admit
        from kamotrace.event_index import prepare
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source = root / "case.json", root / "aws.json"
            source.write_text(json.dumps({"Records": [
                {"eventID": "first", "eventTime": "2026-10-25T00:00:00Z", "eventName": "SendCommand",
                 "eventSource": "ssm.amazonaws.com", "userIdentity": {"userName": "alice", "accessKeyId": "synthetic"},
                 "requestParameters": {"instanceId": "i-synthetic", "number": 9007199254740993}},
                {"eventID": "second", "eventTime": "2026-10-26T00:00:00Z", "eventName": "StartSession"}]}))
            admit(case, "A", "cloudtrail", [source])
            with self.assertRaisesRegex(ValueError, "Preparation required"):
                Store(case=case)
            prepare(case, ["A"], [[1, 2]])
            admit(case, "B", "cloudtrail", [source])
            with self.assertRaisesRegex(ValueError, "Preparation required"):
                Store(case=case)
            with patch("kamotrace.event_index.prepare", side_effect=AssertionError("No startup prepare")):
                store = Store(case=case, units=["A"])
            self.addCleanup(store.selection_directory.cleanup)
            try:
                self.assertEqual(store.meta["total"], 1)
                self.assertEqual(store.meta["case_coverage"]["excluded_units"], ["B"])
                row = store.query({"size": 25})["data"][0]
                self.assertEqual((row["id"], row["identity"], row["key_id"], row["target"]),
                                 (1, "alice", "synthetic", "i-synthetic"))
                self.assertIn("9007199254740993", store.detail(1)["raw_json"])
                self.assertIsNone(store.detail(2))
                self.assertEqual(store.schema({})["case_coverage"], store.meta["case_coverage"])
                server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                url = f"http://127.0.0.1:{server.server_port}"
                try:
                    with http_transport(url) as transport:
                        server.mcp_request = transport
                        async def session():
                            async with Client(url + "/mcp") as client:
                                schema = (await client.call_tool("describe_schema")).structured_content
                                self.assertEqual(schema["case_coverage"], store.coverage)
                                result = (await client.call_tool("search_events", {})).structured_content
                                self.assertEqual(result["total"], 1)
                                context = {k: store.coverage[k] for k in ("case_id", "selection_id")}
                                accepted = await client.call_tool("search_events", {"query": {"case_context": context}})
                                self.assertFalse(accepted.is_error, accepted)
                                stale = {**context, "selection_id": "another-prepared-selection"}
                                for tool, arguments in (("search_events", {}), ("summarize_field", {"field": "event_name"}),
                                        ("event_histogram", {}), ("create_export", {"dataset": "events"})):
                                    rejected = await client.call_tool(tool, {**arguments, "query": {"case_context": stale}})
                                    self.assertTrue(rejected.is_error, (tool, rejected))
                                    self.assertIn("different case/coverage", str(rejected))
                                exported = await client.call_tool("create_export", {"dataset": "events", "fields": ["id"],
                                    "query": {"case_context": context}})
                                self.assertFalse(exported.is_error, exported)
                                with urlopen(exported.structured_content["download_url"]) as response:
                                    manifest, row = [json.loads(line) for line in response]
                                self.assertEqual(manifest["case_coverage"], store.coverage)
                                self.assertEqual(row, {"type": "event", "id": 1})
                                detail = (await client.call_tool("get_event", {"id": 1})).structured_content
                                self.assertIn("9007199254740993", detail["raw_json"])
                        anyio.run(session)
                finally:
                    server.shutdown()
                    worker.join()
                    server.server_close()
            finally:
                if store.exports is not None:
                    store.exports.close()
                store.connection.close()
                store.reviews.close()

    def test_selected_preparation_is_narrow_reusable_and_replaces_partial_coverage(self):
        from kamotrace.datasets import admit, read_case
        from kamotrace.event_index import prepare, verify_prepared
        from kamotrace.importer import sha256
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source = root / "case.json", root / "source.jsonl"
            source.write_text("\n".join(json.dumps({"date": f"2026-10-25T00:00:{i % 60:02d}Z",
                "content": {"ordinal": i, "n": 9007199254740993}}) for i in range(1100)))
            a = admit(case, "A", "generic", [source], "Synthetic")
            b = admit(case, "B", "generic", [source], "Synthetic")
            first = prepare(case, ["A", "B"])
            before = json.loads(json.dumps(first["units"]))
            c = admit(case, "C", "generic", [source], "Synthetic")
            self.assertEqual(read_case(case)["units"][:2], before)
            prepared = prepare(case, ["C"], [[131073, 131075], [131100, 131700]])
            self.assertEqual(prepared["units"][:2], before)
            self.assertEqual(prepared["units"][2]["prepared"]["records"], 602)
            for unit in prepared["units"]:
                with duckdb.connect(str(verify_prepared(prepared, unit)), read_only=True) as connection:
                    columns = {r[0] for r in connection.execute("DESCRIBE event_index").fetchall()}
                    self.assertFalse(columns & {"raw_event", "user_identity", "request_parameters", "response_elements"})
                self.assertEqual(sha256(Path(unit["raw"]["path"])), unit["raw"]["sha256"])
            old = prepared["units"][2]["prepared"]
            replaced = prepare(case, ["C"], [[131074, 131077]])
            self.assertEqual(replaced["units"][2]["prepared"]["records"], 3)
            self.assertEqual(sha256(Path(old["path"])), old["sha256"])
            with patch("kamotrace.datasets.durable_publish", side_effect=OSError("synthetic output failure")):
                with self.assertRaisesRegex(OSError, "output failure"):
                    prepare(case, ["C"])
            self.assertEqual(read_case(case), replaced)
            # Idempotent completed-scope retry does not create another artifact.
            self.assertEqual(prepare(case, ["A"]), replaced)
            artifacts = len(list(root.glob("*.prepared-*.duckdb")))
            with patch("kamotrace.datasets.save_case", side_effect=OSError("synthetic manifest failure")):
                with self.assertRaisesRegex(OSError, "manifest failure"):
                    prepare(case, ["C"])
            self.assertEqual(read_case(case), replaced)
            self.assertEqual(len(list(root.glob("*.prepared-*.duckdb"))), artifacts + 1)
            # Corrupt only a disposable synthetic derived artifact, never source evidence.
            damaged = Path(replaced["units"][2]["prepared"]["path"])
            damaged.write_bytes(b"synthetic corrupt derived output")
            with self.assertRaisesRegex(ValueError, "artifact changed"):
                prepare(case, ["C"], [[131074, 131077]])
            rebuilt = prepare(case, ["C"], [[131074, 131077]], rebuild=True)
            self.assertEqual(rebuilt["units"][:2], before)
            self.assertNotEqual(rebuilt["units"][2]["prepared"]["path"], str(damaged))
            self.assertEqual(damaged.read_bytes(), b"synthetic corrupt derived output")

    def test_raw_units_retry_duplicates_and_manifest_last_failure(self):
        from kamotrace.datasets import admit, read_case, verify_artifact
        from kamotrace.importer import sha256
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source = root / "case.json", root / "source.jsonl"
            raw = '{"date":"2026-10-25T23:59:59Z","content":{"n":9007199254740993,"d":0.1234567890123456789}}'
            source.write_text(raw + "\n" + raw, encoding="utf-8")
            original = sha256(source)
            a = admit(case, "A", "generic", [source], "Synthetic")
            self.assertEqual(a["raw"]["ranges"], [[1, 3]])
            info = read_case(case)
            with duckdb.connect(str(verify_artifact(info, a, "raw")), read_only=True) as connection:
                rows = connection.execute("SELECT source_record, source_ordinal, raw_event FROM raw_events ORDER BY source_record").fetchall()
                self.assertEqual([r[:2] for r in rows], [(1, 1), (2, 2)])
                self.assertIn("9007199254740993", rows[0][2])
                self.assertIn("0.1234567890123456789", rows[0][2])
            before = case.read_bytes()
            self.assertEqual(admit(case, "A", "generic", [source], "Synthetic"), a)
            self.assertEqual(case.read_bytes(), before)
            b = admit(case, "B", "generic", [source], "Synthetic")
            self.assertEqual(b["raw"]["ranges"], [[65537, 65539]])
            self.assertEqual(sha256(Path(a["raw"]["path"])), a["raw"]["sha256"])
            # Fail AFTER raw publication, before registering it. Never auto-adopt it.
            from kamotrace.datasets import save_case
            def fail_registration(path, info, revision):
                if any(u["unit_id"] == "C" for u in info["units"]):
                    raise OSError("synthetic manifest publication failure")
                return save_case(path, info, revision)
            with patch("kamotrace.datasets.save_case", side_effect=fail_registration):
                with self.assertRaisesRegex(OSError, "publication failure"):
                    admit(case, "C", "generic", [source], "Synthetic")
            self.assertEqual([u["unit_id"] for u in read_case(case)["units"]], ["A", "B"])
            self.assertEqual(len(list(root.glob("*.raw-*.duckdb"))), 3)
            c = admit(case, "C", "generic", [source], "Synthetic")
            self.assertEqual(c["raw"]["ranges"], [[196609, 196611]])
            self.assertEqual(len(list(root.glob("*.raw-*.duckdb"))), 4)
            self.assertEqual(sha256(source), original)
            source.write_text(raw + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different inputs"):
                admit(case, "A", "generic", [source], "Synthetic")
            with self.assertRaisesRegex(ValueError, "Preparation required"):
                verify_artifact(read_case(case), a, "prepared")

    def test_reservations_are_durable_sparse_and_fail_closed(self):
        from kamotrace.datasets import case_writer, read_case, reserve, save_case
        from kamotrace.other_events import MANUAL_BASE
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "case.json"
            with case_writer(path) as info:
                initial = json.loads(path.read_text())
                with self.assertRaises(BlockingIOError):
                    with case_writer(path):
                        self.fail("Concurrent writer entered")
                self.assertEqual(reserve(path, info, 7), (1, 8))
                with self.assertRaisesRegex(ValueError, "changed"):
                    save_case(path, initial, initial["revision"])
            # A killed writer never returns its reservation, even without a unit.
            subprocess.run([sys.executable, "-c", """
import os, sys
from kamotrace.datasets import case_writer, reserve
with case_writer(sys.argv[1]) as info:
    reserve(sys.argv[1], info, 13)
    os._exit(0)
""", str(path)], check=True)
            with case_writer(path) as info:
                self.assertEqual(reserve(path, info, 2), (21, 23))
                old = path.read_bytes()
                with patch("kamotrace.datasets.publish", side_effect=OSError("synthetic disk full")):
                    with self.assertRaisesRegex(OSError, "disk full"):
                        reserve(path, info, 31)
                self.assertEqual(path.read_bytes(), old)
            with case_writer(path) as info:
                self.assertEqual(info["next_record"], 23)
                info["next_record"] = MANUAL_BASE - 2
                save_case(path, info, info["revision"])
                self.assertEqual(reserve(path, info, 2), (MANUAL_BASE - 2, MANUAL_BASE))
                with self.assertRaises(ValueError):
                    reserve(path, info, 1)
                with self.assertRaises(ValueError):
                    reserve(path, info, True)
            self.assertEqual(read_case(path)["units"], [])

    def test_manifest_readers_and_post_replace_io_failure_keep_complete_revisions(self):
        from kamotrace.datasets import case_writer, read_case, reserve
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "case.json"
            with case_writer(path):
                pass
            stop = threading.Event()
            started = threading.Event()
            observed = []

            def reader():
                while not stop.is_set():
                    info = read_case(path)
                    observed.append((info["revision"], info["next_record"]))
                    started.set()

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(reader)
                self.assertTrue(started.wait(5))
                try:
                    with case_writer(path) as info:
                        for _ in range(20):
                            reserve(path, info, 7)
                finally:
                    stop.set()
                future.result()
            self.assertTrue(observed)
            self.assertTrue(all(next_record == 1 + revision * 7 for revision, next_record in observed))
            self.assertEqual(read_case(path)["next_record"], 141)
            # Rename has happened before this injected directory-fsync error.
            # Its outcome is uncertain to the writer, so reload, never reuse IDs.
            with self.assertRaisesRegex(OSError, "directory sync"):
                with case_writer(path) as info, patch("kamotrace.datasets.sync_directory",
                        side_effect=OSError("synthetic directory sync failure")):
                    reserve(path, info, 11)
            self.assertEqual(read_case(path)["next_record"], 152)
            with case_writer(path) as info:
                self.assertEqual(reserve(path, info, 3), (152, 155))

    def test_legacy_and_invalid_manifests_are_not_adopted(self):
        from kamotrace.datasets import case_writer, read_case, reserve, validate_case
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "case.json"
            path.write_text('{"kind":"kamotrace-datasets-v1"}')
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "re-ingest"):
                with case_writer(path):
                    self.fail("Legacy manifest adopted")
            self.assertEqual(path.read_bytes(), before)
            path = Path(folder) / "fresh.json"
            with case_writer(path) as info:
                reserve(path, info, 20)
            base = read_case(path)
            raw = {"path": str(Path(folder) / "raw.duckdb"), "sha256": "a" * 64,
                   "records": 2, "ranges": [[1, 3]]}
            unit = {"unit_id": "host-A/acquisition-1", "kind": "uac", "labels": {},
                    "input": {"sha256": "b" * 64}, "raw": raw, "prepared": None}
            base["units"] = [unit]
            validate_case(base, path)
            for ranges in ([[True, 3]], [[1, 3], [3, 5]], [[1, 6], [5, 9]], [[1, 22]]):
                invalid = json.loads(json.dumps(base))
                invalid["units"][0]["raw"]["ranges"] = ranges
                with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                    validate_case(invalid, path)
            duplicate = json.loads(json.dumps(unit))
            duplicate["unit_id"] = "host-B/acquisition-1"
            duplicate["raw"]["path"] = str(Path(folder) / "second.duckdb")
            base["units"].append(duplicate)
            with self.assertRaisesRegex(ValueError, "share issued IDs"):
                validate_case(base, path)


class OtherEventsContract(unittest.TestCase):
    call = BrowserContract.call

    def test_explicit_preparation_reuse_precision_and_read_only_originals(self):
        from kamotrace.datasets import admit, read_case
        from kamotrace.event_index import prepare
        from kamotrace.importer import sha256
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            case, source = root / "case.json", root / "source.jsonl"
            raw = '{"date":"2026-10-25T00:00:00.123456Z","content":{"n":9007199254740993,"d":0.123456789012345678901234567890,"text":"日本語"}}'
            source.write_text(raw + "\n" + raw, encoding="utf-8")
            admit(case, "A", "generic", [source], "Synthetic repeated observations")
            prepare(case, ["A"])
            first = read_case(case)
            prepare(case, ["A"])
            self.assertEqual(read_case(case), first)
            store = Store(case=case)
            try:
                self.assertEqual(store.event_index_status, "attached")
                expected = [store.detail(i) for i in (1, 2)]
                self.assertEqual(expected[0]["record_sha256"], expected[1]["record_sha256"])
                self.assertEqual([d["source_ordinal"] for d in expected], [1, 2])
                self.assertIn("0.123456789012345678901234567890", expected[0]["raw_json"])
                self.assertIn("9007199254740993", expected[0]["raw_json"])
                for table in ("case_raw_0.raw_events", "case_prepared_0.event_index"):
                    with self.assertRaises(duckdb.Error):
                        store.connection.execute("DELETE FROM " + table)
            finally:
                store.connection.close()
                store.reviews.close()
                store.selection_directory.cleanup()
            artifact = first["units"][0]["prepared"]
            self.assertEqual(sha256(Path(artifact["path"])), artifact["sha256"])
            with duckdb.connect(artifact["path"]) as connection:
                connection.execute("UPDATE event_index SET origin='damaged'")
            with self.assertRaisesRegex(ValueError, "artifact changed"):
                Store(case=case)
            # Explicit rebuild, never viewer repair; retain the old published file.
            prepare(case, ["A"], rebuild=True)
            self.assertTrue(Path(artifact["path"]).is_file())
            self.assertNotEqual(read_case(case)["units"][0]["prepared"]["path"], artifact["path"])

    def test_dense_key_positions_are_bounded_and_narrowable(self):
        from kamotrace.other_events import build as import_other
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, database = root / "milestones.jsonl", root / "other.duckdb"
            start = 1792886400
            source.write_text("\n".join(json.dumps({"date": datetime.fromtimestamp(start + i, timezone.utc).isoformat(),
                "content": i}) for i in range(2001)))
            import_other([source], database, "Synthetic dense milestones")
            store = Store(database)
            try:
                rows = [row for page in range(1, 22) for row in store.query({"page": page, "size": 100})["data"]]
                last = max(rows, key=lambda r: r["time_local"])
                hashes = [r["record_sha256"] for r in rows if r["id"] != last["id"]]
                store.review_write({"action": "tag", "slug": "key-event", "color": "#7c3aed", "hashes": hashes})
                histogram = store.histogram({})
                self.assertFalse(histogram["key_positions"]["truncated"])
                self.assertEqual(len(histogram["key_positions"]["positions_ms"]), 2000)
                store.review_write({"action": "tag", "slug": "key-event", "color": "#7c3aed", "hashes": [last["record_sha256"]]})
                histogram = store.histogram({})
                self.assertEqual(histogram["data"][0]["key_events"], 2001)
                self.assertEqual(histogram["data"][0]["key_last_ms"], (start + 2000) * 1000)
                self.assertEqual(histogram["key_positions"], {"positions_ms": [(start + i) * 1000 for i in range(2000)], "truncated": True})
                narrowed = store.histogram({"start": datetime.fromtimestamp(start + 1999, timezone.utc).isoformat()})
                self.assertEqual(narrowed["key_positions"], {"positions_ms": [(start + 1999) * 1000, (start + 2000) * 1000], "truncated": False})
                self.assertTrue(narrowed["overview_key_positions"]["truncated"])
            finally:
                store.connection.close()
                store.reviews.close()

    def test_jsonl_validation_batches_and_provenance(self):
        from kamotrace.cli import main
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, database = root / "payments.jsonl.gz", root / "other.duckdb"
            row = '{"date":"2026-10-25T00:00:00+08:00","content":{"amount":9007199254740993,"fraction":0.123456789012345678901}}'
            source.write_bytes(gzip.compress(((row + "\n") * 1001).encode()))
            self.assertEqual(main(["import-other", "--source", str(source), "--database", str(database),
                                   "--origin", "Synthetic ledger export, converted to JSONL"]), 0)
            store = Store(database)
            try:
                self.assertEqual(store.meta["total"], 1001)
                result = store.query({"size": 25, "page": 41, "raw_fields": ["raw.content.amount", "raw.content.fraction"]})
                self.assertEqual(result["data"][0]["raw_fields"]["raw.content.amount"]["value"], "9007199254740993")
                self.assertEqual(result["data"][0]["raw_fields"]["raw.content.fraction"]["value"], "0.123456789012345678901")
                store.review_write({"action": "tag", "hashes": [result["data"][0]["record_sha256"]],
                                    "slug": "duplicates", "color": "#c45436"})
                self.assertEqual(store.query({"tags": ["duplicates"]})["last_row"], 1001)
                detail = store.detail(1001)
                self.assertEqual(detail["provenance"]["source_ordinal"], 1001)
                self.assertEqual(detail["provenance"]["imports"][0]["sources"][0]["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            finally:
                store.connection.close()
                store.reviews.close()
            before = database.read_bytes()
            with self.assertRaises(SystemExit):
                main(["import-other", "--source", str(source), "--database", str(database), "--origin", "Replacement"])
            self.assertEqual(database.read_bytes(), before)
            for invalid in ('{}', '{"date":"2026-10-25","content":"x"}',
                            '{"date":"2026-10-25T00:00:00Z","content":null}',
                            '{"date":"2026-10-25T00:00:00Z","content":"x","ip":"not-an-ip"}'):
                with self.subTest(invalid=invalid):
                    bad = root / "invalid.jsonl"
                    bad.write_text(row + "\n" + invalid)
                    output = root / "invalid.duckdb"
                    with self.assertRaises(SystemExit):
                        main(["import-other", "--source", str(bad), "--database", str(output), "--origin", "Test"])
                    self.assertFalse(output.exists())

    def test_combined_timeline_manual_edits_reviews_and_mcp(self):
        from kamotrace.other_events import build as import_other
        with tempfile.TemporaryDirectory() as folder, ExitStack() as cleanup:
            root = Path(folder)
            aws, other = root / "aws.duckdb", root / "other.duckdb"
            source = root / "aws.json"
            source.write_text('{"Records":[{"eventTime":"2026-10-24T16:00:00Z","eventID":"aws-1","eventName":"ConsoleLogin"}]}')
            build(source, aws)
            source = root / "other.jsonl"
            source.write_text('\n{"date":"2026-10-25T00:00:00+08:00","content":{"payment":9007199254740993},"ip":"2001:db8::1","identity":"customer-42"}\n'
                              '{"date":"2026-10-25T00:00:01+08:00","content":"later"}')
            import_other([source], other, "Synthetic payment ledger")
            original = {p: p.read_bytes() for p in (aws, other)}
            store = Store(aws, other_events=[other])
            cleanup.callback(store.connection.close)
            cleanup.callback(store.reviews.close)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            cleanup.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cleanup.callback(thread.join)
            cleanup.callback(server.shutdown)
            self.url = f"http://127.0.0.1:{server.server_port}"
            server.mcp_request = cleanup.enter_context(http_transport(self.url))

            def rest(route, body=None, status=200):
                code, value = self.call(route, body)
                self.assertEqual(code, status, value)
                return value

            self.assertEqual({r["event_type"] for r in rest("/api/events", {})["data"]}, {"other", "cloudtrail"})
            other_rows = rest("/api/events", {"filters": [{"field": "event_type", "op": "eq", "value": "other"}]})["data"]
            self.assertTrue(all(r["event_name"] is None and r["event_source"] is None for r in other_rows))
            self.assertTrue(all(r["source_label"] == "Synthetic payment ledger" for r in other_rows))
            self.assertEqual(rest("/api/meta")["facets"]["event_name"], ["ConsoleLogin"])
            selection = {"start": "2026-10-25T00:00:00+08:00", "end": "2026-10-25T00:00:01+08:00",
                         "pipeline_version": 1, "pipeline": 'event_type = "other" OR event_type = "cloudtrail"'}
            self.assertEqual(rest("/api/events", selection)["last_row"], 2)
            self.assertEqual(rest("/api/histogram", selection)["total"], 2)
            raw = '{"date":"2026-10-25T00:00:00+08:00","content":{"description":"Unauthorised payment <script>neverRun()</script>","amount":9007199254740993,"fraction":0.123456789012345678901}}'
            manual_search = {"search": "Unauthorised payment"}
            self.assertEqual(rest("/api/histogram", manual_search)["total"], 0)
            new = rest("/api/manual-events", {"record_json": raw, "origin": "Statement review", "author": "Analyst one"})
            self.assertEqual(rest("/api/events", manual_search)["last_row"], 1)
            self.assertEqual(rest("/api/histogram", manual_search)["total"], 1)
            rest("/api/reviews", {"action": "tag", "hashes": [new["record_sha256"]], "slug": "key-event", "color": "#c45436"})
            note = rest("/api/reviews", {"action": "annotate", "hashes": [new["record_sha256"]], "body": "Synthetic finding"})
            self.assertEqual(rest("/api/histogram", manual_search)["total"], 1)
            changed = {"id": new["id"], "updated": new["updated"], "record_json": raw.replace("Unauthorised payment", "Corrected payment"),
                       "origin": "Statement review, corrected", "author": "Analyst two"}
            edit = rest("/api/manual-events", changed)
            self.assertEqual(edit["record_sha256"], new["record_sha256"])
            self.assertEqual(rest("/api/histogram", manual_search)["total"], 0)
            self.assertEqual(rest("/api/events", {"search": "Corrected payment"})["last_row"], 1)
            rest("/api/manual-events", changed, status=409)
            rest("/api/manual-events", {**changed, "id": 2}, status=400)
            detail = rest(f"/api/events/{new['id']}")
            self.assertIn("9007199254740993", detail["editor"]["content_json"])
            self.assertIn("0.123456789012345678901", detail["editor"]["content_json"])
            self.assertEqual(detail["revisions"][0]["author"], "Analyst one")
            self.assertIn("Unauthorised payment", detail["revisions"][0]["raw_json"])
            self.assertEqual(hashlib.sha256(detail["raw_json"].encode()).hexdigest(), detail["content_sha256"])
            tagged = rest("/api/events", {"tags": ["key-event"], "annotation_id": note["id"]})
            self.assertEqual([r["id"] for r in tagged["data"]], [new["id"]])
            self.assertEqual(rest("/api/column-values", {"field": "event_type"})["total"], 4)
            export = rest("/api/exports", {"dataset": "events", "selection": {"tags": ["key-event"]}})
            cleanup.callback(store.exports.close)
            with urlopen(export["download_url"]) as response:
                exported = [json.loads(line) for line in response.read().splitlines()]
            self.assertEqual(exported[1]["provenance"]["origin"], changed["origin"])
            self.assertEqual(exported[1]["raw_json"], detail["raw_json"])

            async def session():
                async with Client(self.url + "/mcp") as client:
                    schema = await client.call_tool("describe_schema", {})
                    self.assertTrue(schema.structured_content["manual_events_writable"])
                    result = await client.call_tool("search_events", {"query": {"pipeline_version": 1, "pipeline": 'event_type = "manual"'}})
                    self.assertEqual(result.structured_content["total"], 1)
                    event = await client.call_tool("get_event", {"id": new["id"]})
                    self.assertTrue(event.structured_content["raw_json_matches_hash"])
                    added = await client.call_tool("create_manual_event", {"record_json": raw, "origin": "MCP analyst note"})
                    self.assertFalse(added.is_error, added)
                    value = added.structured_content
                    amended = await client.call_tool("edit_manual_event", {"id": value["id"], "updated": value["updated"],
                        "record_json": raw.replace("Unauthorised", "Reported"), "origin": "MCP analyst correction"})
                    self.assertFalse(amended.is_error, amended)
                    existing = rest("/api/events", {})["data"]
                    hashes = [r["record_sha256"] for r in existing if r["event_type"] != "manual"]
                    marked = await client.call_tool("tag_events", {"tag": "key-event", "hashes": hashes})
                    self.assertFalse(marked.is_error, marked)
                    histogram = await client.call_tool("event_histogram", {"query": {"timezone": "Asia/Singapore"}})
                    self.assertFalse(histogram.is_error, histogram)
                    self.assertEqual(sum(r["key_events"] for r in histogram.structured_content["buckets"]), 4)
                    self.assertEqual(len(histogram.structured_content["key_positions"]["positions_ms"]), 2)
                    scoped = await client.call_tool("search_events", {"query": {"pipeline_version": 1, "pipeline": 'tag = "key-event"'}})
                    self.assertFalse(scoped.is_error, scoped)
                    self.assertEqual(scoped.structured_content["total"], 4)
                    removed = await client.call_tool("untag_events", {"tag": "key-event", "hashes": hashes})
                    self.assertFalse(removed.is_error, removed)
            anyio.run(session)
            cleanup.close()  # Reopen after stopping the sole owner of the case and annotations.
            reopened = Store(aws, other_events=[other])
            try:
                self.assertEqual(reopened.query({"tags": ["key-event"]})["last_row"], 1)
                self.assertEqual(reopened.meta["total"], 5)
                self.assertEqual(reopened.detail(new["id"])["raw_json"], detail["raw_json"])
            finally:
                reopened.connection.close()
                reopened.reviews.close()
            for path, before in original.items():
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
