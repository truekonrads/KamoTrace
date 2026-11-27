"""Public EKS CLI/auto contracts, real SDK request validation and offline REST/MCP imports."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from functools import partial
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

import anyio
from boto3 import Session
from botocore.stub import Stubber
import duckdb
from mcp import Client, StdioServerParameters

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
            "arn": f"arn:aws:eks:{REGION}:123456789012:cluster/current", "version": "1.34",
            "endpoint": "https://synthetic.eks.example", "resourcesVpcConfig": {"vpcId": "vpc-eks",
                "subnetIds": ["subnet-control"], "clusterSecurityGroupId": "sg-control",
                "endpointPublicAccess": True, "endpointPrivateAccess": False, "publicAccessCidrs": ["192.0.2.0/24"]},
            "accessConfig": {"authenticationMode": "API"}, "computeConfig": {"enabled": True}}}, {"name": "current"})
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
            response_key, arn_key = {"describe_nodegroup": ("nodegroup", "nodegroupArn"),
                "describe_fargate_profile": ("fargateProfile", "fargateProfileArn"),
                "describe_addon": ("addon", "addonArn")}[describe]
            record = {param: name, arn_key: f"arn:aws:eks:{REGION}:123456789012:{response_key}/current/{name}/synthetic",
                      "clusterName": "current", "status": "ACTIVE"}
            if describe == "describe_nodegroup":
                record.update(subnets=["subnet-workers"], nodeRole=principal)
            stub.add_response(describe, {response_key: record}, {"clusterName": "current", param: name})
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
            self.assertIn(f"--eks-export {export}", text)
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
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("Inventory startup must be offline")):
            store = Store(database, eks_export=export)
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
        with urlopen(url + "/api/inventory") as response:
            report = json.load(response)
        self.assertTrue(report["loaded"])
        self.assertEqual(len(report["resources"]), 4)
        self.assertEqual(len(report["relationships"]), 3)
        self.assertEqual({r["status"] for r in report["resources"]}, {"Unknown"})
        cluster = next(r for r in report["resources"] if r["kind"] == "EKS cluster")
        worker = next(r for r in report["resources"] if r["kind"] == "EKS node group")
        self.assertEqual(cluster["security_groups"], ["sg-control"])
        self.assertEqual(worker["security_groups"], [])
        self.assertEqual(worker["subnet_ids"], ["subnet-workers"])
        self.assertEqual(worker["vpc_id"], "vpc-eks")
        self.assertEqual(report["metadata"]["eks"]["files"], info["files"])
        self.assertTrue(any(op["status"] == "error" for op in report["eks_coverage"]))
        self.assertTrue(any(p["operation"] == "describe_pod_identity_association" for p in cluster["details"]["observations"]))
        self.assertEqual(store.inventory.lookup("machine", cluster["id"], "123456789012", REGION)[0]["resource"], cluster)
        query = {"pipeline_version": 1, "pipeline": 'event_type = "other" | search "CloudWatch log event"', "start": START, "end": END}
        with urlopen(Request(url + "/api/events", data=json.dumps(query).encode(), headers={"Content-Type": "application/json"})) as response:
            self.assertEqual(json.load(response)["last_row"], 3)
        for label, ids in [("explicit", {2, 3}), ("registered", {4, 5, 6})]:
            with urlopen(Request(url + "/api/events", data=json.dumps({"search": "existing-" + label}).encode(),
                                 headers={"Content-Type": "application/json"})) as response:
                self.assertEqual({r["id"] for r in json.load(response)["data"]}, ids)

        async def check():
            async with Client(url + "/mcp") as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                for name in ("get_inventory", "search_eks_pods"):
                    self.assertTrue(tools[name].annotations.read_only_hint)
                    self.assertFalse(tools[name].annotations.open_world_hint)
                inventory = await client.call_tool("get_inventory", {})
                self.assertFalse(inventory.is_error, inventory)
                overview = inventory.structured_content
                self.assertNotIn("resources", overview)
                categories = {row["category"]: row for row in overview["categories"]}
                for name in ("vpcs", "subnets", "security_groups", "forwarding_paths", "listener_actions", "iam.roles"):
                    self.assertFalse(categories[name]["available"], name)
                missing_network = await client.call_tool("get_inventory", {"category": "vpcs"})
                self.assertFalse(missing_network.is_error, missing_network)
                self.assertFalse(missing_network.structured_content["available"])
                self.assertEqual(missing_network.structured_content["total"], 0)
                self.assertTrue(categories["relationships"]["available"])
                self.assertEqual(next(c["total"] for c in overview["categories"] if c["category"] == "resources"), 4)
                self.assertEqual(overview["eks_snapshot"]["finished_at"], info["finished_at"])
                self.assertGreater(overview["coverage"]["eks_gaps"], 0)
                clusters = await client.call_tool("get_inventory", {"category": "resources", "kind": "EKS cluster"})
                self.assertFalse(clusters.is_error, clusters)
                self.assertEqual([r["id"] for r in clusters.structured_content["data"]], [cluster["id"]])
                detailed = await client.call_tool("get_inventory", {"category": "resources", "resource_id": cluster["id"],
                    "region": REGION, "account": "123456789012", "include_details": True})
                self.assertFalse(detailed.is_error, detailed)
                self.assertEqual(detailed.structured_content["data"], [cluster])
                coverage = await client.call_tool("get_inventory", {"category": "eks_coverage", "include_details": True})
                self.assertFalse(coverage.is_error, coverage)
                self.assertCountEqual(coverage.structured_content["data"], report["eks_coverage"])
                self.assertIsNone(store.eks_pod_sources)  # Inventory reads never scan historical logs.
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

    def test_eks_inventory_overlay_preserves_scope_sources_and_failures(self):
        from kamotrace.inventory_store import Inventory

        export, _ = self.collect()
        network = self.root / "network"
        network.mkdir()
        report = Inventory().report
        report["metadata"] = {"account": "123456789012", "started_at_utc": "2026-09-01T00:00:00Z",
                              "completed_at_utc": "2026-09-01T00:01:00Z", "regions": [REGION]}
        report["security_groups"] = [{"id": "sg-control", "name": "control", "region": region, "resources": []}
                                     for region in (REGION, "us-east-1")]
        path = network / "report.json"
        path.write_text(json.dumps(report))
        before = sha256(path)
        with patch("kamotrace.eks.boto3.Session", side_effect=AssertionError("Overlay must be offline")):
            combined = Inventory(network, export).report
        self.assertEqual(combined["metadata"]["completed_at_utc"], report["metadata"]["completed_at_utc"])
        self.assertNotEqual(combined["metadata"]["eks"]["finished_at"], report["metadata"]["completed_at_utc"])
        self.assertEqual(len(combined["security_groups"][0]["resources"]), 1)
        self.assertEqual(combined["security_groups"][1]["resources"], [])
        self.assertEqual(sha256(path), before)
        report["metadata"]["account"] = "999999999999"
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "same AWS account"):
            Inventory(network, export)
        (export / "raw.jsonl").write_text("modified")
        with self.assertRaisesRegex(ValueError, "EKS source changed"):
            Inventory(eks_export=export)

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


class PodObservationsContract(unittest.TestCase):
    def test_mcp_pod_coverage_is_bounded_and_evidence_linked(self):
        from kamotrace import other_events

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            databases = []
            for dataset in range(2):
                rows = [{"date": START, "content": {"kind": "kamotrace-eks-v1", "complete": True,
                    "collection": dataset * 6 + i, "warnings": ["Synthetic collection gap"],
                    "operations": [{"operation": "synthetic", "description": "x" * 120,
                                    "status": "error" if op == 199 else "retrieved"} for op in range(200)]}}
                    for i in range(6)]
                rows.append({"date": START, "content": {"kind": "CloudWatch log event", "account": "123456789012", "region": REGION,
                    "log_group": "/aws/eks/large/cluster", "event": {"message": json.dumps({"kubernetes": {
                        "pod_name": str(dataset) + "p" * 8000, "namespace_name": "jobs"}})}}})
                source, database = root / f"source-{dataset}.jsonl", root / f"source-{dataset}.duckdb"
                source.write_text("\n".join(json.dumps(row) for row in rows))
                other_events.build([source], database, eks.ORIGIN)
                databases.append(database)
            before = {path: sha256(path) for path in databases}
            store = Store(databases[0], other_events=databases[1:])
            stack.callback(store.selection_directory.cleanup)
            stack.callback(store.connection.close)
            stack.callback(store.reviews.close)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            stack.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            url = f"http://127.0.0.1:{server.server_port}"
            server.mcp_request = stack.enter_context(http_transport(url))
            scope = {"account": "123456789012", "region": REGION, "cluster": "empty"}
            with urlopen(Request(url + "/api/eks-pods", data=json.dumps(scope).encode(), headers={"Content-Type": "application/json"})) as response:
                full = json.load(response)
            self.assertGreater(len(json.dumps(full).encode()), 400000)
            self.assertEqual(len(full["coverage"]["datasets"]), 2)

            async def check(transport):
                async with Client(transport) as client:
                    pages = []
                    for page in (1, 2):
                        result = await client.call_tool("search_eks_pods", {**scope, "coverage_page": page})
                        self.assertFalse(result.is_error, result)
                        self.assertLess(len(result.model_dump_json().encode()), 80000)
                        self.assertEqual(result.structured_content["total"], 0)
                        pages.append(result.structured_content["coverage"])
                    self.assertEqual(pages[0]["datasets_total"], 2)
                    self.assertEqual(pages[0]["coverage_records_total"], 12)
                    self.assertEqual([page["coverage_next_page"] for page in pages], [2, None])
                    links = [link for page in pages for link in page["coverage_records"]]
                    self.assertEqual([link["id"] for link in links], [*range(1, 7), *range(8, 14)])
                    self.assertEqual({link["operations_with_gaps"] for link in links}, {1})
                    original = await client.call_tool("get_event", {"id": links[-1]["id"]})
                    self.assertTrue(original.structured_content["raw_json_matches_hash"])
                    self.assertEqual(original.structured_content["record_sha256"], links[-1]["record_sha256"])
                    self.assertEqual(len(json.loads(original.structured_content["raw_json"])["content"]["operations"]), 200)
                    rejected = await client.call_tool("search_eks_pods", {**scope, "cluster": "large", "size": 2})
                    self.assertTrue(rejected.is_error, rejected)
                    self.assertIn("reduce size", rejected.content[0].text)
                    for page in (1, 2):
                        result = await client.call_tool("search_eks_pods", {**scope, "cluster": "large", "size": 1, "page": page})
                        self.assertFalse(result.is_error, result)
                        self.assertEqual(result.structured_content["total"], 2)
                        self.assertEqual(result.structured_content["data"][0]["pod"], str(2 - page) + "p" * 8000)
            for transport in (url + "/mcp", StdioServerParameters(command=sys.executable, args=["-m", "kamotrace", "mcp", "--url", url])):
                anyio.run(check, transport)
            self.assertEqual({path: sha256(path) for path in before}, before)

    def test_combined_import_preserves_each_coverage_record(self):
        from kamotrace import other_events

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            manifests = [
                {"kind": "kamotrace-eks-v1", "complete": True,
                 "scope": {"max_bytes": 32}, "warnings": ["Earlier collection truncated"],
                 "operations": [{"operation": "log_retrieval", "status": "log_limit"}]},
                {"kind": "EKS collection coverage (not historical completeness)",
                 "scope": {"max_bytes": 64},
                 "operations": [{"operation": "log_retrieval", "status": "retrieved"}]},
            ]
            sources = [root / "first.jsonl", root / "second.jsonl"]
            for source, manifest in zip(sources, manifests):
                source.write_text(json.dumps({"date": START, "content": manifest}))
            database = root / "combined.duckdb"
            other_events.build(sources, database, eks.ORIGIN)
            before = {path: sha256(path) for path in [*sources, database]}
            store = Store(database)
            stack.callback(store.selection_directory.cleanup)
            stack.callback(store.connection.close)
            stack.callback(store.reviews.close)
            dataset = store.eks_pods({"account": "123456789012", "region": REGION, "cluster": "current"})["coverage"]["datasets"][0]
            self.assertIsNone(dataset["manifest"])  # A combined dataset has no single collection scope.
            self.assertEqual([row["manifest"] for row in dataset["coverage_records"]], manifests)
            self.assertEqual([row["id"] for row in dataset["coverage_records"]], [1, 2])
            for row, source in zip(dataset["coverage_records"], sources):
                detail = store.detail(row["id"])
                self.assertEqual(row["record_sha256"], detail["record_sha256"])
                self.assertEqual(row["manifest"], json.loads(detail["raw_json"])["content"])
                self.assertEqual(detail["provenance"]["source_file"], str(source))
            self.assertEqual({path: sha256(path) for path in before}, before)

    def test_offline_http_caller_target_separation_scope_and_source_identity(self):
        from copy import deepcopy
        from kamotrace import importer, other_events

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            primary = root / "ct.duckdb"
            ct = root / "ct.json"
            ct.write_text(json.dumps({"Records": [{"eventID": str(i), "eventTime": START} for i in range(2)]}))
            importer.build([ct], primary)
            preceding = root / "existing.jsonl"
            preceding.write_text("\n".join(json.dumps({"date": START, "content": "unrelated"}) for _ in range(3)))
            unrelated = root / "unrelated.duckdb"
            other_events.build([preceding], unrelated, "Existing unrelated dataset")
            caller = {"username": "system:serviceaccount:operations:controller", "extra": {
                "authentication.kubernetes.io/" + key: [value] for key, value in
                (("pod-name", "caller-7"), ("pod-uid", "caller-uid"), ("node-name", "credential-node-3"), ("node-uid", "node-uid"))}}
            audit = {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "auditID": "one-request",
                     "stage": "RequestReceived", "verb": "create", "user": caller,
                     "objectRef": {"resource": "pods", "namespace": "target-ns", "name": "reused", "uid": "target-old", "subresource": "exec"},
                     "precise": 9007199254740993}
            records = []

            def log(message, delta, **overrides):
                content = {"kind": "CloudWatch log event", "account": "123456789012", "region": REGION,
                           "log_group": "/aws/eks/historical/cluster", "acquired_at": "2026-10-02T01:02:03Z",
                           "event": {"message": json.dumps(message) if not isinstance(message, str) else message,
                                     "timestamp": LOW + delta, "ingestionTime": HIGH + 50,
                                     "eventId": f"source-{len(records)}", "logStreamName": "kube-apiserver-audit-synthetic"}, **overrides}
                records.append({"date": datetime.fromtimestamp((LOW + delta) / 1000, timezone.utc).isoformat(), "content": content})

            log(audit, 0)
            completed = deepcopy(audit)
            completed.update(stage="ResponseComplete", responseStatus={"code": 403})
            completed["objectRef"]["uid"] = "target-new"
            log(completed, 100)
            listing = deepcopy(audit)
            listing.update(verb="list", stage="ResponseComplete", objectRef={"resource": "pods", "namespace": "target-ns"}, responseStatus={"code": 404})
            log(listing, 200)  # Caller remains explicit; list does not invent a named target.
            review = deepcopy(audit)
            review.update(user={"username": "reviewer"}, objectRef={"resource": "subjectaccessreviews"},
                          requestObject={"kind": "SubjectAccessReview", "spec": {"extra": caller["extra"]}})
            log(review, 300)  # Reviewed subject credentials are not the authenticated caller.
            workload = {"kubernetes": {"pod_name": "worker-2", "pod_id": "worker-uid", "namespace_name": "jobs", "cluster_name": "historical"}, "log": "untrusted <script>"}
            log(workload, 400, log_group="/workloads/application")
            del workload["kubernetes"]["cluster_name"]
            log(workload, 500, log_group="/workloads/unattributed")
            log("unstructured log", 600)
            log(audit, 1000)  # Exactly the exclusive end.
            log(audit, 700, account="999999999999")
            log(audit, 800, region="us-east-1")
            log(audit, 900, log_group="/aws/eks/other/cluster")
            manifest = {"kind": "kamotrace-eks-v1", "complete": True, "scope": {"start_ms": LOW, "end_exclusive_ms": HIGH},
                        "operations": [{"operation": "log_retrieval", "status": "log_limit"}]}
            records.append({"date": END, "content": manifest})
            source, dataset = root / "events.jsonl", root / "eks.duckdb"
            source.write_text("\n".join(json.dumps(row) for row in records))
            other_events.build([source], dataset, eks.ORIGIN)
            before = {p: sha256(p) for p in (source, primary, unrelated, dataset)}
            with patch("boto3.Session", side_effect=AssertionError("Pod extraction must be offline")):
                store = Store(primary, other_events=[unrelated, dataset])
                stack.callback(store.selection_directory.cleanup)
                stack.callback(store.connection.close)
                stack.callback(store.reviews.close)
                server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                stack.callback(server.server_close)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                stack.callback(thread.join)
                stack.callback(server.shutdown)
                url = f"http://127.0.0.1:{server.server_port}"
                query = {"account": "123456789012", "region": REGION, "cluster": "historical", "start": START, "end": END}
                server.mcp_request = stack.enter_context(http_transport(url))

                def request(body):
                    with urlopen(Request(url + "/api/eks-pods", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})) as response:
                        return json.load(response)

                result = request(query)
                self.assertEqual(result["total"], 6)
                self.assertEqual(result["total_contexts"], 4)
                self.assertEqual({(r["observation_role"], r["uid"], r["observations"]) for r in result["contexts"]}, {
                    ("Authenticated caller", "caller-uid", 3), ("Target pod", "target-old", 1),
                    ("Target pod", "target-new", 1), ("Workload metadata", "worker-uid", 1)})
                self.assertEqual([r["observation_role"] for r in result["data"]].count("Authenticated caller"), 3)
                targets = [r for r in result["data"] if r["observation_role"] == "Target pod"]
                self.assertEqual({r["uid"] for r in targets}, {"target-old", "target-new"})
                callers = [r for r in result["data"] if r["observation_role"] == "Authenticated caller"]
                self.assertEqual({(r["pod"], r["namespace"], r["uid"], r["node"]) for r in callers}, {("caller-7", "operations", "caller-uid", "credential-node-3")})
                self.assertEqual({r["outcome"] for r in targets}, {"Outcome not recorded", "API response 403"})
                self.assertEqual({r["stage"] for r in targets}, {"RequestReceived", "ResponseComplete"})
                self.assertEqual(result["coverage"]["datasets"][0]["dataset_index"], 2)
                self.assertEqual(result["coverage"]["datasets"][0]["manifest"], manifest)
                self.assertEqual(result["coverage"]["log_events"], 6)
                self.assertEqual(datetime.fromisoformat(result["coverage"]["first_log_time"]).timestamp(), LOW / 1000)
                self.assertEqual(datetime.fromisoformat(result["coverage"]["last_log_time"]).timestamp(), (LOW + 600) / 1000)
                self.assertEqual(result["coverage"]["malformed_messages"], 1)
                self.assertEqual(result["coverage"]["unresolved_cluster_events"], 1)
                self.assertEqual(request({**query, "pod": "reused", "uid": "target-old"})["total"], 1)
                self.assertEqual(request({**query, "pod": "reused", "namespace": "operations"})["total"], 0)
                self.assertEqual(request({**query, "pod": "' OR true --"})["total"], 0)
                target = next(r for r in targets if r["uid"] == "target-old")
                self.assertEqual(target["id"], 6)  # Two CloudTrail + three unrelated rows precede this source.
                with urlopen(url + "/api/events/6") as response:
                    detail = json.load(response)
                self.assertEqual(detail["record_sha256"], target["record_sha256"])
                self.assertEqual(json.loads(detail["raw_json"])["content"]["event"]["message"], records[0]["content"]["event"]["message"])
                self.assertEqual(target["source"]["event_id"], "source-0")

                async def check():
                    async with Client(url + "/mcp") as client:
                        inventory = await client.call_tool("get_inventory", {})
                        self.assertFalse(inventory.is_error, inventory)
                        self.assertFalse(inventory.structured_content["loaded"])
                        pods = await client.call_tool("search_eks_pods", query)
                        self.assertFalse(pods.is_error, pods)
                        self.assertEqual(pods.structured_content["data"], result["data"])
                        self.assertEqual(pods.structured_content["contexts"], result["contexts"])
                        self.assertEqual(pods.structured_content, request({**query, "projection": "summary", "size": 10}))
                        self.assertEqual(pods.structured_content["coverage"]["coverage_records"][0]["id"], 17)
                        for filters, expected in (({"pod": "reused", "uid": "target-old"}, 1),
                                                  ({"pod": "reused", "namespace": "operations"}, 0),
                                                  ({"account": "999999999999"}, 2),
                                                  ({"region": "us-east-1"}, 2),
                                                  ({"cluster": "other"}, 2),
                                                  ({"pod": "' OR true --"}, 0),
                                                  ({"start": "2026-10-01T08:00:00.001+08:00", "end": "2026-10-01T08:00:00.100+08:00"}, 0),
                                                  ({"page": 2}, 0)):
                            selected = await client.call_tool("search_eks_pods", {**query, **filters})
                            self.assertFalse(selected.is_error, selected)
                            self.assertEqual(len(selected.structured_content["data"]), expected)
                        original = await client.call_tool("get_event", {"id": target["id"]})
                        self.assertTrue(original.structured_content["raw_json_matches_hash"])
                        self.assertEqual(original.structured_content["record_sha256"], target["record_sha256"])
                        for invalid in ({**query, "start": END}, {**query, "page": True},
                                        {**query, "size": 0}, {**query, "size": 51}, {**query, "coverage_page": True},
                                        {**query, "account": ""}, {"region": REGION, "cluster": "historical"}):
                            rejected = await client.call_tool("search_eks_pods", invalid)
                            self.assertTrue(rejected.is_error, rejected)
                anyio.run(check)
                from urllib.error import HTTPError
                for invalid in ({**query, "start": END}, {**query, "page": True}, {**query, "size": 0},
                                {**query, "coverage_page": True}, {**query, "projection": "unknown"}, {**query, "sql": "SELECT *"}):
                    with self.assertRaises(HTTPError) as raised:
                        request(invalid)
                    self.assertEqual(raised.exception.code, 400)
            self.assertEqual({p: sha256(p) for p in before}, before)

    def test_primary_eks_dataset_pagination_and_unknown_coverage(self):
        from kamotrace import other_events

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, database = root / "events.jsonl", root / "events.duckdb"
            message = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "stage": "ResponseStarted",
                       "verb": "watch", "objectRef": {"resource": "pods", "name": "same-name", "namespace": "jobs"}}
            source.write_text("\n".join(json.dumps({"date": START, "content": {"kind": "CloudWatch log event", "account": "123456789012", "region": REGION,
                "log_group": "/aws/eks/historical/cluster", "event": {"message": json.dumps({**message, "objectRef": {**message["objectRef"], "name": f"pod-{i}"}}), "eventId": str(i)}}}) for i in range(53)))
            other_events.build([source], database, eks.ORIGIN)
            with patch("boto3.Session", side_effect=AssertionError("Offline only")):
                store = Store(database)
                try:
                    query = {"account": "123456789012", "region": REGION, "cluster": "historical"}
                    first, second = store.eks_pods(query), store.eks_pods({**query, "page": 2})
                    self.assertEqual((first["total"], len(first["data"]), len(second["data"])), (53, 50, 3))
                    self.assertEqual([r["id"] for r in first["data"] + second["data"]], list(range(53, 0, -1)))
                    self.assertTrue(all(r["uid"] is None for r in first["data"]))
                    self.assertEqual(first["total_contexts"], 53)
                    self.assertEqual(len(first["contexts"]), 50)
                    self.assertEqual({r["observations"] for r in first["contexts"]}, {1})
                    self.assertIsNone(first["coverage"]["datasets"][0]["manifest"])
                    self.assertEqual(store.eks_pods({**query, "uid": "unobserved"})["total"], 0)
                    with ExitStack() as stack:
                        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
                        stack.callback(server.server_close)
                        thread = threading.Thread(target=server.serve_forever, daemon=True)
                        thread.start()
                        stack.callback(thread.join)
                        stack.callback(server.shutdown)
                        url = f"http://127.0.0.1:{server.server_port}"
                        server.mcp_request = stack.enter_context(http_transport(url))

                        async def check():
                            async with Client(url + "/mcp") as client:
                                ids = []
                                for page in range(1, 7):
                                    result = await client.call_tool("search_eks_pods", {**query, "page": page})
                                    self.assertFalse(result.is_error, result)
                                    value = result.structured_content
                                    self.assertEqual((value["total"], value["total_contexts"]), (53, 53))
                                    self.assertEqual(value["next_page"], page + 1 if page < 6 else None)
                                    self.assertEqual(len(value["contexts"]), 10)
                                    self.assertEqual(value["coverage"]["datasets_without_coverage"], 1)
                                    self.assertEqual(value["coverage"]["coverage_records_total"], 0)
                                    ids.extend(row["id"] for row in value["data"])
                                self.assertEqual(ids, list(range(53, 0, -1)))
                        anyio.run(check)
                finally:
                    store.connection.close()
                    store.reviews.close()
                    store.selection_directory.cleanup()
