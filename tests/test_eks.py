"""Public EKS CLI/auto contracts, real SDK request validation and offline REST/MCP imports."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from functools import partial
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

import anyio
from boto3 import Session
from botocore.stub import Stubber
import duckdb
from mcp import Client

from kamotrace.cli import main
from kamotrace import eks
from kamotrace.importer import sha256
from kamotrace.server import Handler, Store
from kamotrace.mcp_server import http_transport
from kamotrace.suzaku import evidence_identity

REGION = "ap-southeast-3"
START, END = "2026-10-01T00:00:00Z", "2026-10-01T00:00:01Z"
LOW, HIGH = 1790812800000, 1790812801000
GROUP = "/aws/eks/deleted/cluster"
MESSAGE = '{"auditID":"same-audit","stage":"ResponseComplete","precise":9007199254740993}'


class EKSContract(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        session = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=REGION)
        self.clients, self.stubs = {}, {}
        for service in ("sts", "eks", "logs"):
            client = session.client(service)
            stub = self.stack.enter_context(Stubber(client))
            self.clients[service], self.stubs[service] = client, stub
        self.stack.enter_context(patch("kamotrace.eks.boto3.Session", return_value=self))
        self.stubs["sts"].add_response("get_caller_identity", {"Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/synthetic", "UserId": "synthetic"}, {})

    def client(self, service, **kwargs):
        return self.clients[service]

    def run_cli(self, *argv, status=0):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            try:
                actual = main(list(map(str, argv)))
            except SystemExit as error:
                actual = error.code
        self.assertEqual(0 if actual is None else actual, status, output.getvalue())
        return output.getvalue()

    def inventory(self):
        stub = self.stubs["eks"]
        stub.add_response("list_clusters", {"clusters": ["current"]}, {})
        stub.add_response("describe_cluster", {"cluster": {"name": "current", "status": "ACTIVE",
            "computeConfig": {"enabled": True}}}, {"name": "current"})
        principal = "arn:aws:iam::123456789012:role/platform"
        stub.add_response("list_access_entries", {"accessEntries": [principal], "nextToken": "entries-next"}, {"clusterName": "current"})
        stub.add_response("list_access_entries", {"accessEntries": []}, {"clusterName": "current", "nextToken": "entries-next"})
        stub.add_response("describe_access_entry", {"accessEntry": {"principalArn": principal, "type": "STANDARD"}},
                          {"clusterName": "current", "principalArn": principal})
        stub.add_response("list_associated_access_policies", {"associatedAccessPolicies": [{"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
            "accessScope": {"type": "namespace", "namespaces": ["payments"]}}]}, {"clusterName": "current", "principalArn": principal})
        stub.add_response("list_pod_identity_associations", {"associations": [{"associationId": "a-synthetic"}]}, {"clusterName": "current"})
        stub.add_response("describe_pod_identity_association", {"association": {"namespace": "payments", "serviceAccount": "reporter",
            "roleArn": principal}}, {"clusterName": "current", "associationId": "a-synthetic"})
        for operation, key, describe, param, name in [
            ("list_nodegroups", "nodegroups", "describe_nodegroup", "nodegroupName", "workers"),
            ("list_fargate_profiles", "fargateProfileNames", "describe_fargate_profile", "fargateProfileName", "serverless"),
            ("list_addons", "addons", "describe_addon", "addonName", "vpc-cni"),
        ]:
            stub.add_response(operation, {key: [name]}, {"clusterName": "current"})
            stub.add_response(describe, {}, {"clusterName": "current", param: name})
        stub.add_client_error("list_identity_provider_configs", service_error_code="AccessDeniedException",
                              service_message="synthetic denied", expected_params={"clusterName": "current"})

    def groups(self, extra=False):
        stub = self.stubs["logs"]
        stub.add_response("describe_log_groups", {"logGroups": [{"logGroupName": GROUP, "retentionInDays": 90,
            "logGroupClass": "STANDARD"}], "nextToken": "groups-next"}, {"logGroupNamePrefix": "/aws/eks/"})
        stub.add_response("describe_log_groups", {"logGroups": []}, {"logGroupNamePrefix": "/aws/eks/", "nextToken": "groups-next"})
        if extra:
            stub.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "/workloads/app", "logGroupClass": "STANDARD"}]},
                              {"logGroupNamePrefix": "/workloads/app"})
        stub.add_response("describe_log_streams", {"logStreams": [], "nextToken": "stream-next"}, {"logGroupName": GROUP})
        stub.add_response("describe_log_streams", {"logStreams": [{"logStreamName": "kube-apiserver-audit-synthetic"}]},
                          {"logGroupName": GROUP, "nextToken": "stream-next"})

    def collect(self, *, extra=False, max_events=100000, max_bytes=104857600):
        self.inventory()
        self.groups(extra)
        params = {"logGroupName": GROUP, "startTime": LOW, "endTime": HIGH, "limit": min(1000, max_events)}
        self.stubs["logs"].add_response("filter_log_events", {"events": [], "nextToken": "empty-but-more"}, params)
        events = [{"eventId": str(i), "timestamp": stamp, "ingestionTime": HIGH + 99,
                   "logStreamName": "kube-apiserver-audit-synthetic", "message": MESSAGE}
                  for i, stamp in enumerate([LOW - 1, LOW, HIGH - 1, HIGH])]
        response = {"events": [events[1]], "nextToken": "further-page"} if max_events == 1 else {"events": events}
        self.stubs["logs"].add_response("filter_log_events", response, {**params, "nextToken": "empty-but-more"})
        if extra:
            self.stubs["logs"].add_response("describe_log_streams", {"logStreams": []}, {"logGroupName": "/workloads/app"})
            self.stubs["logs"].add_response("filter_log_events", {"events": [{"timestamp": LOW + 29, "message": "workload-original"}]},
                {**params, "logGroupName": "/workloads/app"})
        output, database = self.root / "export", self.root / "eks.duckdb"
        self.run_cli("eks", "--output", output, "--database", database, "--regions", REGION,
            "--start", START, "--end", END, "--max-events", max_events, "--max-bytes", max_bytes,
            *(["--log-group", REGION + ":/workloads/app"] if extra else []))
        return output, database

    def test_collection_offline_import_auto_and_real_mcp(self):
        export, dataset = self.collect(extra=True)
        info = eks.read_export(export)
        self.assertEqual(info["log_events"], 3)
        self.assertTrue(any(op["status"] == "error" and op["operation"] == "list_identity_provider_configs" for op in info["operations"]))
        with duckdb.connect(str(dataset), read_only=True) as db:
            raw = db.execute("SELECT raw_event FROM raw_events WHERE raw_event->>'$.content.kind' = 'CloudWatch log event' ORDER BY source_record").fetchall()
        self.assertEqual([json.loads(row[0])["content"]["event"]["message"] for row in raw], [MESSAGE, MESSAGE, "workload-original"])
        self.assertIn("9007199254740993", raw[0][0])
        hashes = {p: sha256(p) for p in (export / "raw.jsonl", export / "events.jsonl", dataset)}
        ct = self.root / "ct.json"
        ct.write_text('{"Records":[{"eventID":"synthetic","eventTime":"2026-10-01T00:00:00Z","eventName":"ConsoleLogin"}]}')
        target = self.root / "case"
        database = target / "case.duckdb"
        self.run_cli("import", "--source", ct, "--database", database)
        additional = []
        for label, count in [("explicit", 2), ("registered", 3)]:
            source = self.root / (label + ".jsonl")
            source.write_text("\n".join(json.dumps({"date": START, "content": f"existing-{label}-{i}"}) for i in range(count)))
            path = self.root / (label + ".duckdb")
            self.run_cli("import-other", "--source", source, "--database", path, "--origin", label)
            additional.append(path)
        with duckdb.connect(str(database), read_only=True) as connection:
            identity = list(evidence_identity(connection))
        with duckdb.connect(str(database.with_suffix(".uac.duckdb"))) as connection:
            connection.execute("CREATE TABLE build_info(metadata JSON)")
            connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps({"format": "kamotrace-uac-registry-v1", "evidence": identity,
                "imports": [{"database": str(additional[1]), "sha256": sha256(additional[1])}], "attempts": []})])
        argv = ["auto", target, "--source", ct, "--eks-export", export, "--other-events", additional[0],
                "--skip-inventory", "--skip-suzaku", "--skip-enrich", "--no-serve"]
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("Offline must not contact AWS")):
            text = self.run_cli(*argv)
            self.assertIn("--other-events", text)
            self.run_cli(*argv)
            self.run_cli("eks", "--from-export", export, "--database", self.root / "offline.duckdb")
        command = text.split("start later with: ", 1)[1].strip()
        attachments = [Path(path) for path in re.findall(r"--other-events (.*?)(?= --other-events |$)", command)]
        self.assertEqual(attachments, [*additional, target / "case.eks.duckdb"])
        binding_path = database.with_suffix(".datasets.json")
        original_binding = json.loads(binding_path.read_text())
        late_source, late = self.root / "late.jsonl", self.root / "late.duckdb"
        late_source.write_text("\n".join(json.dumps({"date": START, "content": f"later-arrival-{i}"}) for i in range(4)))
        self.run_cli("import-other", "--source", late_source, "--database", late, "--origin", "later arrival")
        # A UAC-style registered arrival after EKS must not move EKS or earlier datasets.
        with duckdb.connect(str(database.with_suffix(".uac.duckdb"))) as connection:
            value = json.loads(connection.execute("SELECT metadata FROM build_info").fetchone()[0])
            value["imports"].append({"database": str(late), "sha256": sha256(late)})
            connection.execute("UPDATE build_info SET metadata=?", [json.dumps(value)])
        with self.assertRaisesRegex(ValueError, "registered with kamotrace auto"):
            Store(database)
        self.assertEqual(json.loads(binding_path.read_text()), original_binding)
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("Adding offline data must not contact AWS")):
            self.run_cli("auto", target, "--source", ct, "--skip-inventory", "--skip-suzaku", "--skip-enrich", "--no-serve")
        new_binding = json.loads(binding_path.read_text())
        self.assertEqual(new_binding["datasets"][:3], original_binding["datasets"])
        self.assertEqual(new_binding["datasets"][3]["database"], str(late))
        # No repeated --other-events flags are needed when reopening the recorded case.
        store = Store(database)
        self.stack.callback(store.connection.close)
        self.stack.callback(store.reviews.close)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
        self.stack.callback(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.stack.callback(thread.join)
        self.stack.callback(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}"
        server.mcp_request = self.stack.enter_context(http_transport(url))
        query = {"pipeline_version": 1, "pipeline": 'event_type = "other" | search "CloudWatch log event"', "start": START, "end": END}
        with urlopen(Request(url + "/api/events", data=json.dumps(query).encode(), headers={"Content-Type": "application/json"})) as response:
            self.assertEqual(json.load(response)["last_row"], 3)
        for label, ids in [("explicit", {2, 3}), ("registered", {4, 5, 6})]:
            with urlopen(Request(url + "/api/events", data=json.dumps({"search": "existing-" + label}).encode(),
                                 headers={"Content-Type": "application/json"})) as response:
                self.assertEqual({r["id"] for r in json.load(response)["data"]}, ids)

        async def check():
            async with Client(url + "/mcp") as client:
                result = await client.call_tool("search_events", {"query": {"pipeline_version": 1,
                    "pipeline": 'event_type = "other" | search "CloudWatch log event"'}})
                self.assertFalse(result.is_error, result)
                self.assertEqual(result.structured_content["total"], 3)
                detail = await client.call_tool("get_event", {"id": result.structured_content["events"][0]["id"]})
                self.assertTrue(detail.structured_content["raw_json_matches_hash"])
        anyio.run(check)
        self.assertEqual({p: sha256(p) for p in hashes}, hashes)
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def test_budgets_keep_raw_pages_but_never_claim_complete_logs(self):
        export, dataset = self.collect(max_events=1)
        info = eks.read_export(export)
        self.assertEqual(info["log_events"], 1)
        self.assertTrue(any(op["operation"] == "log_retrieval" and op["status"] == "log_limit" for op in info["operations"]))
        self.assertIn("further-page", (export / "raw.jsonl").read_text())
        self.run_cli("eks", "--output", export, "--regions", REGION, status=1)
        before = sha256(dataset)
        (export / "events.jsonl").write_text("altered")
        self.run_cli("eks", "--from-export", export, "--database", self.root / "changed.duckdb", status=1)
        self.assertEqual(sha256(dataset), before)

    def test_byte_budget_retains_acquired_page_and_marks_truncation(self):
        export, _ = self.collect(max_bytes=1)
        info = eks.read_export(export)
        self.assertEqual(info["log_events"], 0)
        self.assertGreater(info["received_log_message_bytes"], 1)
        self.assertTrue(any(op["status"] == "log_limit" for op in info["operations"]))

    def test_online_auto_inventory_resume_and_scope_change(self):
        self.stubs["eks"].add_response("list_clusters", {"clusters": []}, {})
        self.stubs["logs"].add_response("describe_log_groups", {"logGroups": []}, {"logGroupNamePrefix": "/aws/eks/"})
        ct = self.root / "ct.json"
        ct.write_text('{"Records":[{"eventID":"synthetic","eventTime":"2026-10-01T00:00:00Z"}]}')
        target = self.root / "case"
        args = ["auto", target, "--source", ct, "--regions", REGION, "--collect-eks", "--skip-inventory", "--skip-suzaku", "--skip-enrich", "--no-serve"]
        self.run_cli(*args)
        before = sha256(target / "case.duckdb")
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("Resume must not contact AWS")):
            self.run_cli(*args)
            self.run_cli(*args, "--eks-max-events", 1, status=1)
        self.assertEqual(sha256(target / "case.duckdb"), before)
        self.assertIn("--other-events", self.run_cli(*args))
        binding = (target / "case.duckdb").with_suffix(".datasets.json")
        original = binding.read_text()
        invalid = json.loads(original)
        invalid["datasets"][0]["offset"] += 1
        binding.write_text(json.dumps(invalid))
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("No AWS retry for an invalid local binding")):
            self.run_cli(*args, status=1)
        self.assertEqual(json.loads(binding.read_text()), invalid)
        self.assertEqual(sha256(target / "case.duckdb"), before)

    def test_log_volume_warning_threshold_and_unknown_sizes(self):
        cases = [(399_999_999, True, False), (400_000_000, True, True),
                 (None, True, False), (700_000_000, False, False)]
        for index, (second_size, read_logs, warn) in enumerate(cases):
            with self.subTest(second_size=second_size, read_logs=read_logs):
                if index:
                    self.stubs["sts"].add_response("get_caller_identity", {"Account": "123456789012",
                        "Arn": "arn:aws:iam::123456789012:user/synthetic", "UserId": "synthetic"}, {})
                self.stubs["eks"].add_response("list_clusters", {"clusters": []}, {})
                second = {"logGroupName": "/aws/eks/second/cluster"}
                if second_size is not None:
                    second["storedBytes"] = second_size
                groups = [{"logGroupName": GROUP, "storedBytes": 600_000_000}, second,
                          {"logGroupName": "/aws/eks/unselected", "storedBytes": 90_000_000_000}]
                self.stubs["logs"].add_response("describe_log_groups", {"logGroups": groups},
                    {"logGroupNamePrefix": "/aws/eks/"})
                for group in groups[:2]:
                    self.stubs["logs"].add_response("describe_log_streams", {"logStreams": []},
                        {"logGroupName": group["logGroupName"]})
                    if read_logs:
                        self.stubs["logs"].add_response("filter_log_events", {"events": []},
                            {"logGroupName": group["logGroupName"], "startTime": LOW, "endTime": HIGH, "limit": 1000})
                export = self.root / f"volume-{index}"
                text = self.run_cli("eks", "--output", export, "--regions", REGION,
                    *(["--start", START, "--end", END] if read_logs else []))
                warnings = eks.read_export(export)["warnings"]
                self.assertEqual(bool(warnings), warn)
                self.assertEqual("WARNING:" in text, warn)
                if warn:
                    self.assertIn("1,000,000,000 stored bytes", text)
                    self.assertIn("not an estimate for the requested time window", text)
                    self.assertIn("104,857,600 bytes", text)
                    rows = [json.loads(line) for line in (export / "events.jsonl").read_text().splitlines()]
                    self.assertEqual(rows[-1]["content"]["warnings"], warnings)
                for stub in self.stubs.values():
                    stub.assert_no_pending_responses()

    def test_unsupported_log_class_and_repeated_empty_page_token(self):
        self.stubs["eks"].add_response("list_clusters", {"clusters": []}, {})
        self.stubs["logs"].add_response("describe_log_groups", {"logGroups": [
            {"logGroupName": GROUP, "logGroupClass": "STANDARD"},
            {"logGroupName": "/aws/eks/rare/cluster", "logGroupClass": "INFREQUENT_ACCESS"}]},
            {"logGroupNamePrefix": "/aws/eks/"})
        self.stubs["logs"].add_response("describe_log_streams", {"logStreams": []}, {"logGroupName": GROUP})
        params = {"logGroupName": GROUP, "startTime": LOW, "endTime": HIGH, "limit": 1000}
        self.stubs["logs"].add_response("filter_log_events", {"events": [], "nextToken": "loop"}, params)
        self.stubs["logs"].add_response("filter_log_events", {"events": [], "nextToken": "loop"}, {**params, "nextToken": "loop"})
        self.stubs["logs"].add_response("describe_log_streams", {"logStreams": []}, {"logGroupName": "/aws/eks/rare/cluster"})
        export = self.root / "classes"
        self.run_cli("eks", "--output", export, "--regions", REGION, "--start", START, "--end", END)
        info = eks.read_export(export)
        self.assertEqual(info["log_events"], 0)
        statuses = {op["status"] for op in info["operations"]}
        self.assertTrue({"repeated_token", "unsupported_log_class"} <= statuses)
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def test_inventory_only_and_global_call_limit(self):
        self.stubs["eks"].add_response("list_clusters", {"clusters": []}, {})
        export = self.root / "limited"
        self.run_cli("eks", "--output", export, "--regions", REGION, "--max-calls", 1)
        info = eks.read_export(export)
        self.assertEqual((info["calls"], info["log_events"]), (1, 0))
        self.assertTrue(any(op["status"] == "call_limit" for op in info["operations"]))
        self.run_cli("eks", "--output", self.root / "invalid", "--regions", REGION, "--start", START, status=1)
        self.assertFalse((self.root / "invalid").exists())
