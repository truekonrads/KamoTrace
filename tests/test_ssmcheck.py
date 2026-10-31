"""Public `kamotrace ssmcheck` contracts against AWS SDK-validated synthetic responses (no AWS access)."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from boto3.session import Session
from botocore.stub import Stubber

from kamotrace.cli import main

SECRET = "synthetic-parameter-value-must-not-appear"


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def session_doc(session_type, **inputs):
    return {"Name": "x", "Content": json.dumps({"schemaVersion": "1.0", "sessionType": session_type, "inputs": inputs}),
            "DocumentFormat": "JSON"}


def denied(stub, method, code="AccessDeniedException"):
    stub.add_client_error(method, service_error_code=code, service_message="denied for arn:aws:iam::1:role/x")


class SsmCheckContract(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        self.clients, self.stubs = {}, {}
        for service, region in [("sts", "us-east-1"), ("ec2", "us-east-1"),
                                ("ssm", "us-east-1"), ("ssm", "ap-southeast-1")]:
            client = sdk.client(service, region_name=region)
            self.clients[service, region] = client
            self.stubs[service, region] = self.stack.enter_context(Stubber(client))
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda service, region_name, **kw: self.clients[service, region_name]
        self.stack.enter_context(patch("kamotrace.ssmcheck.boto3.Session", return_value=session))
        self.stubs["sts", "us-east-1"].add_response("get_caller_identity", {
            "Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/Reader/someone",
            "UserId": "AROASYNTHETIC:someone"})

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["ssmcheck", *args])
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()
        return code, out.getvalue(), err.getvalue()

    def configured_region(self):
        """ap-southeast-1: logging configured in several places, plus an SSH session and inline-only command."""
        ssm = self.stubs["ssm", "ap-southeast-1"]
        ssm.add_response("get_document", session_doc(
            "Standard_Stream", s3BucketName="session-logs", s3KeyPrefix="ssm/", s3EncryptionEnabled=True,
            cloudWatchLogGroupName="/ssm/sessions", cloudWatchEncryptionEnabled=False, cloudWatchStreamingEnabled=True,
            kmsKeyId="alias/session", runAsEnabled=False, shellProfile={"linux": SECRET, "windows": ""}),
            {"Name": "SSM-SessionManagerRunShell", "DocumentFormat": "JSON"})
        ssm.add_response("list_documents", {"DocumentIdentifiers": [
            {"Name": "SSM-SessionManagerRunShell"}, {"Name": "Team-Shell"}, {"Name": "Team-Tunnel"}]},
            {"Filters": [{"Key": "DocumentType", "Values": ["Session"]}, {"Key": "Owner", "Values": ["Self"]}]})
        ssm.add_response("get_document", session_doc("Standard_Stream", s3BucketName="", cloudWatchLogGroupName="/team"),
                         {"Name": "Team-Shell", "DocumentFormat": "JSON"})
        ssm.add_response("describe_sessions", {"Sessions": [
            {"SessionId": "a-1", "DocumentName": "SSM-SessionManagerRunShell", "StartDate": dt("2026-10-20T01:00:00Z")}]},
            {"State": "Active"})
        ssm.add_response("describe_sessions", {"Sessions": [
            {"SessionId": "h-1", "DocumentName": "AWS-StartSSHSession", "StartDate": dt("2026-10-10T01:00:00Z")},
            {"SessionId": "h-2", "StartDate": dt("2026-10-11T01:00:00Z"),
             "OutputUrl": {"S3OutputUrl": "https://s3/session-logs/ssm/h-2.log", "CloudWatchOutputUrl": "https://cw"}},
            {"SessionId": "h-3", "DocumentName": "AWS-StartSSHSession", "StartDate": dt("2026-10-12T01:00:00Z")}]},
            {"State": "History"})
        ssm.add_response("get_document", session_doc("Port", portNumber="22"),
                         {"Name": "AWS-StartSSHSession", "DocumentFormat": "JSON"})
        ssm.add_response("list_commands", {"Commands": [
            {"CommandId": "10000000-0000-0000-0000-000000000000", "DocumentName": "AWS-RunShellScript", "RequestedDateTime": dt("2026-10-05T00:00:00Z"),
             "Parameters": {"commands": [SECRET]}, "OutputS3BucketName": "cmd-out", "OutputS3KeyPrefix": "run/"},
            {"CommandId": "20000000-0000-0000-0000-000000000000", "DocumentName": "AWS-RunPowerShellScript", "RequestedDateTime": dt("2026-10-06T00:00:00Z"),
             "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": True}},
            {"CommandId": "30000000-0000-0000-0000-000000000000", "DocumentName": "AWS-RunShellScript", "RequestedDateTime": dt("2026-10-07T00:00:00Z"),
             "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": False, "CloudWatchLogGroupName": "/ignored"}}]})
        ssm.add_response("list_associations", {"Associations": [{"AssociationId": "11111111-1111-1111-1111-111111111111",
                                                                  "AssociationName": "inventory", "Name": "AWS-GatherSoftwareInventory"}]})
        ssm.add_response("describe_association", {"AssociationDescription": {
            "AssociationId": "11111111-1111-1111-1111-111111111111", "Name": "AWS-GatherSoftwareInventory",
            "Parameters": {"secret": [SECRET]},
            "OutputLocation": {"S3Location": {"OutputS3BucketName": "assoc-out", "OutputS3KeyPrefix": "inv/",
                                              "OutputS3Region": "ap-southeast-1"}}}},
            {"AssociationId": "11111111-1111-1111-1111-111111111111"})
        ssm.add_response("describe_maintenance_windows", {"WindowIdentities": [{"WindowId": "mw-0123456789abcdef0", "Name": "patch"}]})
        ssm.add_response("describe_maintenance_window_tasks", {"Tasks": [
            {"WindowId": "mw-0123456789abcdef0", "WindowTaskId": "22222222-2222-2222-2222-222222222222",
             "TaskArn": "AWS-RunPatchBaseline", "Type": "RUN_COMMAND"},
            {"WindowId": "mw-0123456789abcdef0", "WindowTaskId": "33333333-3333-3333-3333-333333333333",
             "TaskArn": "AWS-RestartEC2Instance", "Type": "AUTOMATION"}]}, {"WindowId": "mw-0123456789abcdef0"})
        ssm.add_response("get_maintenance_window_task", {
            "WindowId": "mw-0123456789abcdef0", "WindowTaskId": "22222222-2222-2222-2222-222222222222",
            "TaskArn": "AWS-RunPatchBaseline", "TaskType": "RUN_COMMAND",
            "TaskInvocationParameters": {"RunCommand": {"Parameters": {"Operation": [SECRET]},
                                                        "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": True}}}},
            {"WindowId": "mw-0123456789abcdef0", "WindowTaskId": "22222222-2222-2222-2222-222222222222"})

    def test_configured_absent_denied_and_truncated_regions_are_distinguished(self):
        self.configured_region()
        ssm = self.stubs["ssm", "us-east-1"]
        ssm.add_client_error("get_document", service_error_code="InvalidDocument", service_message="missing")
        denied(ssm, "list_documents")
        ssm.add_response("describe_sessions", {"Sessions": []}, {"State": "Active"})
        ssm.add_response("describe_sessions", {"Sessions": [
            {"SessionId": "h-9", "DocumentName": "SSM-SessionManagerRunShell", "StartDate": dt("2026-10-01T00:00:00Z")},
            {"SessionId": "h-8", "DocumentName": "SSM-SessionManagerRunShell", "StartDate": dt("2026-10-02T00:00:00Z")},
            {"SessionId": "h-7", "DocumentName": "SSM-SessionManagerRunShell", "StartDate": dt("2026-10-03T00:00:00Z")}]},
            {"State": "History"})
        ssm.add_response("list_commands", {"Commands": []})
        denied(ssm, "list_associations", "AccessDenied")
        ssm.add_response("describe_maintenance_windows", {"WindowIdentities": []})
        target = self.folder / "report.json"

        code, out, err = self.run_cli("--regions", "us-east-1", "ap-southeast-1", "--json", str(target), "--max-items", "2")

        self.assertEqual(code, 1, err)
        raw = target.read_text(encoding="utf-8")
        for leak in (SECRET, "someone", "assumed-role", "denied for", "synthetic"):
            self.assertNotIn(leak, raw + out)
        report = json.loads(raw)
        self.assertEqual((report["tool"], report["version"], report["account_id"], report["complete"]),
                         ("ssmcheck", 1, "123456789012", False))
        self.assertEqual(report["regions"]["checked"], ["ap-southeast-1", "us-east-1"])
        self.assertEqual(sorted((e["region"], e["api"], e["code"], e["state"]) for e in report["errors"]), [
            ("us-east-1", "ssm:ListAssociations", "AccessDenied", "denied"),
            ("us-east-1", "ssm:ListDocuments", "AccessDeniedException", "denied")])
        # The --max-items 2 bound: three History sessions returned, two examined and marked truncated.
        self.assertIn({"region": "us-east-1", "section": "sessions_history", "max_items": 2}, report["truncated"])
        ap, us = report["results"]

        prefs = ap["session_preferences"]
        self.assertEqual((prefs["state"], prefs["s3"], prefs["cloudwatch"]), ("configured",
            {"state": "configured", "bucket": "session-logs", "prefix": "ssm/", "encryption_required": True},
            {"state": "configured", "log_group": "/ssm/sessions", "encryption_required": False, "streaming": True}))
        self.assertEqual((prefs["kms_key_id"], prefs["shell_profile_set"]), ("alias/session", True))
        self.assertEqual(us["session_preferences"], {"state": "not_configured", "document": "SSM-SessionManagerRunShell"})
        self.assertEqual(us["session_documents"], {"state": "denied"})
        self.assertEqual(us["associations"], {"state": "denied"})
        # Owner=Self listing can hit the bound too: 3 identifiers > --max-items 2, so Team-Tunnel is not seen.
        docs = ap["session_documents"]
        self.assertTrue(docs["truncated"])
        self.assertEqual([(d["name"], d["session_type"], d["content_logging"]) for d in docs["documents"]],
                         [("Team-Shell", "Standard_Stream", "document_inputs")])
        self.assertEqual((docs["documents"][0]["s3"]["state"], docs["documents"][0]["cloudwatch"]["log_group"]),
                         ("not_configured", "/team"))

        sessions = ap["observed_sessions"]
        self.assertEqual((sessions["state"], sessions["examined"], sessions["truncated"]), ("observed", 3, True))
        self.assertEqual([(g["document"], g["sessions"], g["content_logging"], g["with_s3_output_url"])
                          for g in sessions["by_document"]],
                         [("SSM-SessionManagerRunShell", 2, "regional_preferences", 1),
                          ("AWS-StartSSHSession", 1, "not_logged", 0)])
        self.assertEqual((sessions["oldest_start"], sessions["newest_start"]),
                         ("2026-10-10T01:00:00Z", "2026-10-20T01:00:00Z"))

        commands = ap["observed_commands"]
        self.assertEqual((commands["examined"], commands["truncated"]), (2, True))
        self.assertEqual([(d["s3_bucket"], d["s3_prefix"], d["cloudwatch_log_group"], d["inline_only"], d["commands"])
                          for d in commands["destinations"]],
                         [("cmd-out", "run/", None, False, 1), (None, None, "/aws/ssm/AWS-RunPowerShellScript", False, 1)])
        self.assertEqual(us["observed_commands"]["destinations"], [])
        assoc = ap["associations"]["associations"][0]
        self.assertEqual((assoc["state"], assoc["s3_bucket"], assoc["s3_prefix"]), ("configured", "assoc-out", "inv/"))
        tasks = ap["maintenance_window_tasks"]
        self.assertEqual([(t["state"], t["cloudwatch_log_group"], t["s3_bucket"]) for t in tasks["run_command_tasks"]],
                         [("configured", "/aws/ssm/AWS-RunPatchBaseline", None)])
        self.assertEqual(tasks["other_task_types"], {"AUTOMATION": 1})
        self.assertEqual(us["maintenance_window_tasks"]["state"], "not_configured")

        self.assertIn("Coverage: PARTIAL", out)
        self.assertIn("Session Manager preferences: not configured", out)
        self.assertIn("us-east-1 ssm:ListDocuments: AccessDeniedException", out)
        self.assertIn("AWS-StartSSHSession: 1 session(s), type=Port, logging=not_logged", out)
        self.assertIn("Port sessions", out)

    def test_all_regions_complete_report_to_stdout_and_no_overwrite(self):
        self.stubs["ec2", "us-east-1"].add_response("describe_regions", {"Regions": [{"RegionName": "us-east-1"}]},
                                                     {"AllRegions": False})
        ssm = self.stubs["ssm", "us-east-1"]
        ssm.add_client_error("get_document", service_error_code="InvalidDocument", service_message="missing")
        ssm.add_response("list_documents", {"DocumentIdentifiers": []})
        ssm.add_response("describe_sessions", {"Sessions": []}, {"State": "Active"})
        ssm.add_response("describe_sessions", {"Sessions": []}, {"State": "History"})
        ssm.add_response("list_commands", {"Commands": [
            {"CommandId": "90000000-0000-0000-0000-000000000000", "DocumentName": "AWS-RunShellScript", "RequestedDateTime": dt("2026-10-05T00:00:00Z")}]})
        ssm.add_response("list_associations", {"Associations": []})
        ssm.add_response("describe_maintenance_windows", {"WindowIdentities": []})

        code, out, err = self.run_cli("--json", "-")

        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertTrue(report["complete"])
        self.assertEqual((report["errors"], report["truncated"]), ([], []))
        self.assertEqual(report["regions"], {"requested": ["all"], "checked": ["us-east-1"]})
        region = report["results"][0]
        self.assertEqual(region["observed_commands"]["destinations"], [
            {"s3_bucket": None, "s3_prefix": None, "cloudwatch_log_group": None, "inline_only": True, "commands": 1}])
        self.assertEqual(region["session_documents"]["state"], "not_configured")
        self.assertIn("Coverage: complete", err)
        self.assertIn("1 command(s): inline only (SSM API)", err)

        existing = self.folder / "old.json"
        existing.write_text("keep", encoding="utf-8")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_:
            main(["ssmcheck", "--json", str(existing)])
        self.assertEqual((exit_.exception.code, existing.read_text(encoding="utf-8")), (2, "keep"))


if __name__ == "__main__":
    unittest.main()
