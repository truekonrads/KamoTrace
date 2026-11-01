"""Public combined-policy CLI contracts; validation uses SDK-checked synthetic AWS responses."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from boto3.session import Session
from botocore.stub import Stubber

from kamotrace.cli import main


class CombinedPolicyContract(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["policy", *args])
        return code, out.getvalue(), err.getvalue()

    def test_offline_policy_combines_collectors_and_scopes_deduplicated_destinations(self):
        key = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/synthetic"
        with patch("kamotrace.aws_policy.boto3.Session", side_effect=AssertionError("must be offline")):
            code, out, err = self.run_cli("--partition", "aws-us-gov", "--bucket", "ssm-logs",
                "--bucket", "trail-logs", "--bucket", "ssm-logs", "--kms-key", key, "--kms-key", key)
        self.assertEqual(code, 0, err)
        policy = json.loads(out)
        statements = policy["Statement"]
        actions = [a for s in statements for a in s["Action"]]
        self.assertEqual(len(actions), len(set(actions)))
        self.assertTrue({"cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus", "ssm:GetDocument",
            "ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ec2:GetManagedPrefixListEntries",
            "rds:DescribeDBInstances", "elasticloadbalancing:DescribeRules", "iam:GetInstanceProfile",
            "s3:GetEncryptionConfiguration", "logs:FilterLogEvents", "kms:Decrypt"}.issubset(actions))
        self.assertTrue(all(a.split(":")[1].startswith(("Describe", "Get", "List", "Lookup", "Filter", "Decrypt"))
                            for a in actions))
        by_action = {a: s["Resource"] for s in statements for a in s["Action"]}
        self.assertEqual(by_action["s3:ListBucket"], ["arn:aws-us-gov:s3:::ssm-logs", "arn:aws-us-gov:s3:::trail-logs"])
        self.assertEqual(by_action["s3:GetObject"], ["arn:aws-us-gov:s3:::ssm-logs/*", "arn:aws-us-gov:s3:::trail-logs/*"])
        self.assertEqual(by_action["kms:Decrypt"], [key])
        self.assertTrue(all(s["Effect"] == "Allow" and "Principal" not in s for s in statements))
        self.assertNotIn("REPLACE_WITH", out)
        self.assertIn("No AWS permissions were changed", err)

    def test_templates_no_kms_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder, patch("kamotrace.aws_policy.boto3.Session",
                side_effect=AssertionError("must be offline")):
            path = Path(folder) / "combined.json"
            code, out, err = self.run_cli("--output", str(path))
            self.assertEqual((code, out), (0, ""), err)
            original = path.read_text()
            self.assertIn("REPLACE_WITH_CLOUDTRAIL_BUCKET", original)
            self.assertIn("REPLACE_WITH_SSM_BUCKET", original)
            self.assertIn("REPLACE_WITH_S3_KMS_KEY_ID", original)
            self.assertEqual(self.run_cli("--output", str(path))[0], 2)
            self.assertEqual(path.read_text(), original)
            code, out, err = self.run_cli("--validate")
            self.assertEqual(code, 1, err)
            self.assertIn("Policy not validated", err)
            code, out, err = self.run_cli("--bucket", "plain-logs", "--no-kms")
            self.assertEqual(code, 0, err)
            self.assertNotIn("kms:Decrypt", out)
            self.assertNotIn("REPLACE_WITH", out)

    def test_rejects_resource_wildcards_and_urls_before_emission(self):
        for args in (["--bucket", "*"], ["--bucket", "s3://logs/prefix"], ["--bucket", "logs/*"],
                     ["--kms-key", "alias/logs"], ["--kms-key", "arn:aws:kms:us-east-1:123456789012:key/*"],
                     ["--kms-key", "arn:aws-cn:kms:cn-north-1:123456789012:key/test"]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                self.run_cli(*args)
            self.assertEqual(error.exception.code, 2)

    def test_access_analyzer_validation_handles_pagination_findings_and_denial(self):
        options = ["--bucket", "plain-logs", "--no-kms"]
        document = self.run_cli(*options)[1]
        client = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic",
                         region_name="us-east-1").client("accessanalyzer")
        session = Mock()
        session.client.return_value = client
        request = {"policyDocument": document, "policyType": "IDENTITY_POLICY"}
        with Stubber(client) as stub, patch("kamotrace.aws_policy.boto3.Session", return_value=session):
            stub.add_response("validate_policy", {"findings": [], "nextToken": "second"}, request)
            stub.add_response("validate_policy", {"findings": [{"findingType": "SECURITY_WARNING",
                "issueCode": "SYNTHETIC_SCOPE", "findingDetails": "Review resource scope.",
                "learnMoreLink": "https://example.com", "locations": []}]}, {**request, "nextToken": "second"})
            code, out, err = self.run_cli(*options, "--validate", "--region", "us-east-1")
            self.assertEqual(code, 1, err)
            self.assertEqual(json.loads(out), json.loads(document))
            self.assertIn("SECURITY_WARNING SYNTHETIC_SCOPE", err)
            self.assertIn("1 finding(s)", err)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "reviewed.json"
                path.write_text(document)
                stub.add_response("validate_policy", {"findings": []}, request)
                code, out, err = self.run_cli("--validate-file", str(path))
                self.assertEqual((code, out), (0, ""), err)
                self.assertIn("0 finding(s)", err)
                self.assertEqual(path.read_text(), document)
            stub.add_client_error("validate_policy", service_error_code="AccessDeniedException", expected_params=request)
            code, out, err = self.run_cli(*options, "--validate")
            self.assertEqual(code, 2, err)
            self.assertIn("AccessDeniedException", err)
            self.assertIn("validation is not confirmed", err)
            stub.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
