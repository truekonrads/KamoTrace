"""Observable exposure-report regressions; no AWS access required."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from kamotrace import inventory
from kamotrace.cli import main
from kamotrace.importer import write_lock
from kamotrace.inventory import analyze


def fixture():
    return {
        "region": "test-region", "errors": [], "describe_vpcs": [], "prefix_lists": {},
        "describe_subnets": [], "describe_db_instances": [], "describe_db_clusters": [],
        "load_balancers": [], "classic_load_balancers": [], "target_groups": [], "target_health": {},
        "describe_instances": [{"Instances": [{
            "InstanceId": "i-test", "InstanceType": "t3.small", "ImageId": "ami-test",
            "VpcId": "vpc-test", "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": "sg-test"}],
            "NetworkInterfaces": [{"NetworkInterfaceId": "eni-public", "SubnetId": "subnet-test",
                "Groups": [{"GroupId": "sg-test"}], "Association": {"PublicIp": "54.1.2.3"},
                "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.5"}]}],
        }]}],
        "describe_security_groups": [{"GroupId": "sg-test", "GroupName": "test", "VpcId": "vpc-test",
            "IpPermissions": [{"IpProtocol": "6", "FromPort": 443, "ToPort": 443,
                               "IpRanges": [{"CidrIp": "8.8.8.0/24"}]}]}],
        "describe_route_tables": [{"RouteTableId": "rtb-test", "VpcId": "vpc-test",
            "Associations": [{"Main": True}], "Routes": [
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-test", "State": "active"}]}],
        "describe_internet_gateways": [{"InternetGatewayId": "igw-test",
            "Attachments": [{"VpcId": "vpc-test", "State": "available"}]}],
        "describe_network_acls": [{"NetworkAclId": "acl-test", "Associations": [{"SubnetId": "subnet-test"}],
            "Entries": [{"RuleNumber": 100, "Egress": egress, "Protocol": "-1",
                         "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"} for egress in [False, True]]}],
    }


def lb_fixture():
    data = fixture()
    instance = data["describe_instances"][0]["Instances"][0]
    instance["PrivateIpAddress"] = "10.0.1.5"
    eni = instance["NetworkInterfaces"][0]
    del eni["Association"]
    eni.update(VpcId="vpc-test", AvailabilityZone="test-a", PrivateIpAddress="10.0.1.5")
    data["describe_network_interfaces"] = [eni, {"Description": "ELB public-lb", "SubnetId": "subnet-test",
        "AvailabilityZone": "test-a", "PrivateIpAddress": "10.0.1.7"}]
    data["describe_subnets"] = [{"SubnetId": "subnet-test", "AvailabilityZone": "test-a"}]
    data["describe_route_tables"][0]["Routes"].append({"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"})
    perm = data["describe_security_groups"][0]["IpPermissions"][0]
    perm.update(FromPort=8443, ToPort=8443, IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    data["load_balancers"] = [{"LoadBalancerArn": "public-lb", "LoadBalancerName": "public", "VpcId": "vpc-test",
        "Scheme": "internet-facing", "Type": "network", "State": {"Code": "active"}, "DNSName": "public.example",
        "AvailabilityZones": [{"SubnetId": "subnet-test", "ZoneName": "test-a"}]}]
    data["listeners"] = [{"ListenerArn": "listener-public", "LoadBalancerArn": "public-lb", "Protocol": "TCP", "Port": 443,
        "DefaultActions": [{"Type": "forward", "TargetGroupArn": "tg-test"}]}]
    data["target_groups"] = [{"TargetGroupArn": "tg-test", "TargetGroupName": "backend", "TargetType": "instance",
        "Protocol": "TCP", "Port": 8443, "VpcId": "vpc-test"}]
    data["target_health"] = {"tg-test": [{"Target": {"Id": "i-test", "Port": 8443}, "TargetHealth": {"State": "healthy"}}]}
    data["target_group_attributes"] = {"tg-test": [{"Key": "preserve_client_ip.enabled", "Value": "true"}]}
    return data


class ExposureReportTest(unittest.TestCase):
    def report(self, data):
        return analyze({}, [data])["resources"][0]

    def test_network_ranges_retain_only_associated_ipv4_and_ipv6(self):
        data = fixture()
        data["describe_vpcs"] = [{"VpcId": "vpc-test", "Tags": [{"Key": "Name", "Value": "Network"}],
            "CidrBlockAssociationSet": [
                {"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}},
                {"CidrBlock": "10.1.0.0/16", "CidrBlockState": {"State": "disassociated"}}],
            "Ipv6CidrBlockAssociationSet": [
                {"Ipv6CidrBlock": "2001:db8:1234::/56", "Ipv6CidrBlockState": {"State": "associated"}},
                {"Ipv6CidrBlock": "2001:db8:5678::/56", "Ipv6CidrBlockState": {"State": "associating"}}]}]
        data["describe_subnets"] = [{"SubnetId": "subnet-test", "VpcId": "vpc-test",
            "CidrBlock": "10.0.1.128/25", "AvailabilityZone": "test-a",
            "Ipv6CidrBlockAssociationSet": [
                {"Ipv6CidrBlock": "2001:db8:1234:80::/64", "Ipv6CidrBlockState": {"State": "associated"}},
                {"Ipv6CidrBlock": "2001:db8:5678:80::/64", "Ipv6CidrBlockState": {"State": "disassociated"}}]}]
        report = analyze({}, [data])
        self.assertEqual(report["vpcs"], [{"id": "vpc-test", "name": "Network", "region": "test-region",
                                          "cidr": "10.0.0.0/16, 2001:db8:1234::/56"}])
        self.assertEqual(report["subnets"], [{"id": "subnet-test", "name": "subnet-test", "region": "test-region",
            "vpc_id": "vpc-test", "availability_zone": "test-a", "cidr": "10.0.1.128/25, 2001:db8:1234:80::/64"}])

    def test_sg_address_route_and_missing_evidence(self):
        baseline = fixture()
        self.assertEqual(self.report(baseline)["status"], "Restricted")
        self.assertEqual({(p["source"], p["ports"]) for p in self.report(baseline)["paths"]}, {("8.8.8.0/24", "443")})
        for scenario, expected in [("world", "Allowed"), ("private-source", "Blocked"),
                                   ("no-public-ip", "Blocked"), ("nat-route", "Blocked"),
                                   ("missing-acl", "Unknown"), ("ingress-middlebox", "Unknown"), ("stopped", "Inactive")]:
            with self.subTest(scenario=scenario):
                data = copy.deepcopy(baseline)
                if scenario in ("world", "private-source"):
                    data["describe_security_groups"][0]["IpPermissions"][0]["IpRanges"] = [
                        {"CidrIp": "0.0.0.0/0" if scenario == "world" else "10.0.0.0/8"}]
                elif scenario == "no-public-ip":
                    del data["describe_instances"][0]["Instances"][0]["NetworkInterfaces"][0]["Association"]
                elif scenario == "nat-route":
                    data["describe_route_tables"][0]["Routes"] = [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-test"}]
                elif scenario == "missing-acl":
                    data["describe_network_acls"] = []
                    data["errors"] = [{"operation": "describe_network_acls"}]
                elif scenario == "ingress-middlebox":
                    data["describe_route_tables"].append({"RouteTableId": "rtb-edge", "VpcId": "vpc-test",
                        "Associations": [{"GatewayId": "igw-test"}],
                        "Routes": [{"DestinationCidrBlock": "10.0.1.0/24", "NetworkInterfaceId": "eni-firewall"}]})
                else:
                    data["describe_instances"][0]["Instances"][0]["State"]["Name"] = "stopped"
                self.assertEqual(self.report(data)["status"], expected)

    def test_ordered_acl_and_return_path_must_share_source(self):
        data = fixture()
        acl = data["describe_network_acls"][0]
        acl["Entries"].insert(0, {"RuleNumber": 50, "Egress": False, "Protocol": "6",
            "PortRange": {"From": 443, "To": 443}, "CidrBlock": "8.8.8.0/25", "RuleAction": "deny"})
        r = self.report(data)
        self.assertEqual({p["source"] for p in r["paths"]}, {"8.8.8.128/25"})
        acl["Entries"] = [acl["Entries"][0], acl["Entries"][1],
            {"RuleNumber": 100, "Egress": True, "Protocol": "6", "CidrBlock": "8.8.8.0/25",
             "PortRange": {"From": 1024, "To": 65535}, "RuleAction": "allow"}]
        self.assertEqual(self.report(data)["status"], "Blocked")
        acl["Entries"][2]["CidrBlock"] = "8.8.8.128/25"
        acl["Entries"][2]["PortRange"] = {"From": 443, "To": 443}
        self.assertEqual(self.report(data)["status"], "Blocked")
        acl["Entries"][2]["PortRange"] = {"From": 32768, "To": 32768}
        self.assertEqual(self.report(data)["paths"][0]["source"], "8.8.8.128/25")

    def test_more_specific_route_overrides_default(self):
        data = fixture()
        data["describe_route_tables"][0]["Routes"].append({"DestinationCidrBlock": "8.8.8.0/25", "GatewayId": "igw-test", "State": "blackhole"})
        self.assertEqual({p["source"] for p in self.report(data)["paths"]}, {"8.8.8.128/25"})
        data["describe_route_tables"][0]["Routes"][-1] = {"DestinationPrefixListId": "pl-test", "GatewayId": "vpce-test"}
        data["prefix_lists"]["pl-test"] = [{"Cidr": "8.8.8.0/25"}]
        self.assertEqual({p["source"] for p in self.report(data)["paths"]}, {"8.8.8.128/25"})
        del data["prefix_lists"]["pl-test"]
        self.assertEqual(self.report(data)["status"], "Unknown")

    def test_private_interface_sg_cannot_open_public_interface(self):
        data = fixture()
        public = data["describe_instances"][0]["Instances"][0]["NetworkInterfaces"][0]
        public["Groups"] = [{"GroupId": "sg-closed"}]
        data["describe_security_groups"].append({"GroupId": "sg-closed", "GroupName": "closed", "VpcId": "vpc-test", "IpPermissions": []})
        private = copy.deepcopy(public)
        private["NetworkInterfaceId"] = "eni-private"
        private["Groups"] = [{"GroupId": "sg-test"}]
        del private["Association"]
        data["describe_instances"][0]["Instances"][0]["NetworkInterfaces"].append(private)
        self.assertEqual(self.report(data)["status"], "Blocked")

    def test_rds_uses_database_port_not_unrelated_open_port(self):
        data = fixture()
        data["describe_instances"] = []
        data["describe_db_instances"] = [{"DBInstanceIdentifier": "db", "DBInstanceStatus": "available",
            "DBSubnetGroup": {"VpcId": "vpc-test", "Subnets": [{"SubnetIdentifier": "subnet-test"}]},
            "Endpoint": {"Address": "db.example", "Port": 5432}, "PubliclyAccessible": True,
            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-test"}], "Engine": "postgres", "EngineVersion": "16", "DBInstanceClass": "db.t3.small"}]
        self.assertEqual(self.report(data)["status"], "Blocked")
        perm = data["describe_security_groups"][0]["IpPermissions"][0]
        perm["FromPort"] = perm["ToPort"] = 5432
        self.assertEqual({p["ports"] for p in self.report(data)["paths"]}, {"5432"})

    def test_ipv6_and_egress_only_gateway(self):
        data = fixture()
        eni = data["describe_instances"][0]["Instances"][0]["NetworkInterfaces"][0]
        del eni["Association"]
        eni["Ipv6Addresses"] = [{"Ipv6Address": "2600:1f18::10"}]
        perm = data["describe_security_groups"][0]["IpPermissions"][0]
        perm["IpRanges"] = []
        perm["Ipv6Ranges"] = [{"CidrIpv6": "2606:4700::/48"}]
        route = {"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-test"}
        data["describe_route_tables"][0]["Routes"] = [route]
        for rule in data["describe_network_acls"][0]["Entries"]:
            del rule["CidrBlock"]
            rule["Ipv6CidrBlock"] = "::/0"
        self.assertEqual({p["source"] for p in self.report(data)["paths"]}, {"2606:4700::/48"})
        del route["GatewayId"]
        route["EgressOnlyInternetGatewayId"] = "eigw-test"
        self.assertEqual(self.report(data)["status"], "Blocked")

    def test_role_is_resolved_from_profile_not_inferred_from_profile_name(self):
        data = fixture()
        instance = data["describe_instances"][0]["Instances"][0]
        self.assertEqual(self.report(data)["iam_role_status"], "None assigned")
        arn = "arn:aws:iam::123456789012:instance-profile/team/web-profile"
        instance["IamInstanceProfile"] = {"Arn": arn}
        self.assertEqual(self.report(data)["iam_role_status"], "Unknown")
        role_arn = "arn:aws:iam::123456789012:role/actual-workload-role"
        iam = {"profiles": {arn: {"status": "Resolved", "roles": [{"name": "actual-workload-role", "arn": role_arn}]}}, "errors": []}
        row = analyze({}, [data], iam)["resources"][0]
        self.assertEqual(row["iam_roles"], ["actual-workload-role"])
        self.assertEqual(row["iam_role_arns"], [role_arn])
        self.assertEqual(row["iam_instance_profile"], arn)
        self.assertEqual(row["iam_role_status"], "Resolved")

    def test_private_backend_exposure_uses_target_not_listener_port(self):
        data = lb_fixture()
        report = analyze({}, [data])
        backend = report["resources"][0]
        self.assertEqual((backend["direct_status"], backend["status"]), ("Blocked", "Allowed"))
        self.assertEqual(backend["via_load_balancers"], ["public"])
        route = report["forwarding_paths"][0]
        self.assertEqual((route["listener_port"], route["target_port"], route["network_status"]), (443, 8443, "Allowed"))
        perm = data["describe_security_groups"][0]["IpPermissions"][0]
        perm["IpRanges"] = [{"CidrIp": "8.8.8.0/24"}]
        self.assertEqual(self.report(data)["status"], "Restricted")
        perm.update(FromPort=443, ToPort=443)
        report = analyze({}, [data])
        self.assertEqual(report["resources"][0]["status"], "Blocked")
        self.assertEqual(report["forwarding_paths"][0]["network_status"], "Blocked")

    def test_forwarding_health_weight_empty_and_redirect(self):
        for health in ("healthy", "unhealthy", "unavailable"):
            data = lb_fixture()
            data["target_health"]["tg-test"][0]["TargetHealth"]["State"] = health
            self.assertEqual(self.report(data)["status"], "Allowed")
        for scenario in ("zero-weight", "empty", "redirect"):
            with self.subTest(scenario=scenario):
                data = lb_fixture()
                if scenario == "zero-weight":
                    data["listeners"][0]["DefaultActions"] = [{"Type": "forward", "ForwardConfig": {
                        "TargetGroups": [{"TargetGroupArn": "tg-test", "Weight": 0}]}}]
                elif scenario == "empty":
                    data["target_health"]["tg-test"] = []
                else:
                    data["listeners"][0]["DefaultActions"] = [{"Type": "redirect", "RedirectConfig": {"Port": "443"}}]
                report = analyze({}, [data])
                self.assertEqual(report["resources"][0]["status"], "Blocked")
                self.assertFalse(any(r["public_entry"] for r in report["forwarding_paths"]))
                if scenario == "redirect":
                    self.assertEqual(len(report["listener_actions"]), 1)

    def test_chained_lb_propagates_only_registered_listener_port(self):
        data = lb_fixture()
        internal = copy.deepcopy(data["load_balancers"][0])
        internal.update(LoadBalancerArn="internal-lb", LoadBalancerName="internal", Scheme="internal", Type="application")
        data["load_balancers"].append(internal)
        data["target_groups"][0]["TargetType"] = "alb"
        data["target_health"]["tg-test"][0]["Target"].update(Id="internal-lb", Port=8080)
        for port in (8080, 9090):
            tg = f"lambda-{port}"
            data["target_groups"].append({"TargetGroupArn": tg, "TargetType": "lambda", "VpcId": "vpc-test"})
            data["target_health"][tg] = [{"Target": {"Id": f"arn:aws:lambda:test:123:function:{tg}"}, "TargetHealth": {"State": "unavailable"}}]
            data["listeners"].append({"ListenerArn": f"listener-{port}", "LoadBalancerArn": "internal-lb", "Protocol": "HTTP",
                "Port": port, "DefaultActions": [{"Type": "forward", "TargetGroupArn": tg}]})
        report = analyze({}, [data])
        lambdas = {r["name"]: r for r in report["resources"] if r["kind"] == "Lambda"}
        self.assertEqual(lambdas["lambda-8080"]["indirect_status"], "Configured")
        self.assertEqual(lambdas["lambda-8080"]["status"], "Unknown")
        self.assertEqual(lambdas["lambda-9090"]["indirect_status"], "None")

    def test_backend_acl_requires_same_source_and_ephemeral_return(self):
        data = lb_fixture()
        data["load_balancers"][0]["AvailabilityZones"][0]["SubnetId"] = "subnet-front"
        data["describe_network_interfaces"][1]["SubnetId"] = "subnet-front"
        front_acl = copy.deepcopy(data["describe_network_acls"][0])
        front_acl.update(NetworkAclId="acl-front", Associations=[{"SubnetId": "subnet-front"}])
        data["describe_network_acls"].append(front_acl)
        target_acl = data["describe_network_acls"][0]
        target_acl["Entries"] = [
            {"RuleNumber": 100, "Egress": False, "Protocol": "6", "CidrBlock": "8.8.8.0/25",
             "PortRange": {"From": 8443, "To": 8443}, "RuleAction": "allow"},
            {"RuleNumber": 100, "Egress": True, "Protocol": "6", "CidrBlock": "8.8.8.128/25",
             "PortRange": {"From": 32768, "To": 32768}, "RuleAction": "allow"}]
        self.assertEqual(self.report(data)["status"], "Blocked")
        target_acl["Entries"][1]["CidrBlock"] = "8.8.8.0/25"
        self.assertEqual(self.report(data)["status"], "Allowed")
        target_acl["Entries"][1]["PortRange"] = {"From": 443, "To": 443}
        self.assertEqual(self.report(data)["status"], "Blocked")


class InventoryExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "original"
        inventory.write_json(self.source / "collection.json", {
            "account": "123456789012", "started_at_utc": "2026-01-01T00:00:00+00:00",
            "completed_at_utc": "2026-01-01T00:01:00+00:00", "regions": ["test-region"]})
        inventory.write_json(self.source / "regions" / "test-region.json", fixture())
        (self.source / "raw").mkdir()
        (self.source / "raw" / "page.json").write_bytes(b'{"number": 9007199254740993}\n')

    def cli(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(["inventory", *map(str, args)])

    def test_offline_legacy_export_preserves_raw_provenance_and_report_contract(self):
        before = {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob("*") if p.is_file()}
        out = self.root / "analysis"
        with patch.object(inventory.boto3, "Session", side_effect=AssertionError("offline must not call AWS")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(["inventory", "--from-export", str(self.source), "--output", str(out),
                                       "--emit-policy", "-"]), 0)
            policy = json.loads(stdout.getvalue())
            self.assertIn("Inventory snapshot:", stderr.getvalue())
            self.assertIn("iam:GetInstanceProfile", policy["Statement"][0]["Action"])
        self.assertEqual(before, {p.relative_to(self.source): p.read_bytes() for p in self.source.rglob("*") if p.is_file()})
        for path, value in before.items():
            self.assertEqual((out / path).read_bytes(), value)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report, analyze(*inventory.read_export(self.source)))
        self.assertEqual(report["resources"][0]["status"], "Restricted")
        self.assertIn("not historical", report["metadata"]["limitations"][0])
        self.assertTrue(inventory.completed_export(out))

    def test_inventory_policy_can_be_emitted_without_credentials_or_snapshot(self):
        target = self.root / "policy.json"
        with patch.object(inventory.boto3, "Session", side_effect=AssertionError("policy must not call AWS")):
            self.assertEqual(self.cli("--emit-policy", target), 0)
        policy = json.loads(target.read_text())
        actions = policy["Statement"][0]["Action"]
        self.assertEqual(set(actions), {
            "sts:GetCallerIdentity", "ec2:DescribeRegions", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
            "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups",
            "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNetworkAcls",
            "ec2:GetManagedPrefixListEntries", "rds:DescribeDBInstances", "rds:DescribeDBClusters",
            "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeTargetGroupAttributes",
            "iam:GetInstanceProfile", "iam:GetAccountAuthorizationDetails", "iam:ListPolicies",
            "iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
            "iam:ListMFADevices", "iam:GetLoginProfile"})
        before = target.read_bytes()
        for args in (["--emit-policy", target], ["--output", self.root / "new", "--emit-policy", self.root / "new/policy.json"],
                     ["--from-export", self.source, "--emit-policy", self.source / "policy.json"]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                self.cli(*args)
            self.assertEqual(error.exception.code, 2)
        self.assertEqual(target.read_bytes(), before)

    def test_unknown_existing_targets_inputs_and_locks_are_never_overwritten(self):
        out = self.root / "unknown"
        out.mkdir()
        (out / "keep").write_bytes(b"original")
        self.assertEqual(self.cli("--output", out, "--from-export", self.source), 1)
        self.assertEqual((out / "keep").read_bytes(), b"original")
        for unsafe in (self.source, self.source / "child", self.root):
            self.assertEqual(self.cli("--output", unsafe, "--from-export", self.source), 1)
        out = self.root / "busy"
        with write_lock(out):
            self.assertEqual(self.cli("--output", out, "--from-export", self.source), 1)
        self.assertFalse(out.exists())

    def test_completion_verifies_scope_hashes_missing_files_and_collect_only(self):
        out = inventory.build(self.root / "out", from_export=self.source, regions=["test-region"], profile="test")
        self.assertTrue(inventory.completed_export(out, ["test-region"], "test"))
        self.assertIsNone(inventory.completed_export(out, ["all"], "test"))
        self.assertIsNone(inventory.completed_export(out, ["test-region"], "other"))
        raw = out / "raw" / "page.json"
        original = raw.read_bytes()
        raw.write_bytes(b"altered")
        self.assertIsNone(inventory.completed_export(out))
        raw.write_bytes(original)
        (out / "regions" / "test-region.json").unlink()
        self.assertIsNone(inventory.completed_export(out))
        collected = inventory.build(self.root / "collected", from_export=self.source, collect_only=True)
        self.assertFalse((collected / "report.json").exists())
        self.assertIsNone(inventory.completed_export(collected))
        self.assertEqual(self.cli("--output", self.root / "reanalyzed", "--from-export", collected), 0)

    def test_failed_analysis_publishes_nothing_and_cleans_private_staging(self):
        out = self.root / "out"
        with patch.object(inventory, "analyze", side_effect=ValueError("synthetic")):
            self.assertEqual(self.cli("--output", out, "--from-export", self.source), 1)
        self.assertFalse(out.exists())
        self.assertEqual(list(self.root.glob(".*.staging")), [])

    def test_online_all_regions_and_explicit_iam_account_guard(self):
        session = Mock()
        session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
        session.client.return_value.describe_regions.return_value = {"Regions": [
            {"RegionName": "test-region", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "disabled", "OptInStatus": "not-opted-in"}]}
        def collect(region, profile, out):
            data = fixture()
            inventory.write_json(out / "regions" / (region + ".json"), data)
            return data
        with patch.object(inventory.boto3, "Session", return_value=session), patch.object(inventory, "collect_region", side_effect=collect) as collector, patch.object(inventory, "collect_iam", return_value=None):
            out = inventory.build(self.root / "online")
            self.assertEqual(collector.call_args.args[:2], ("test-region", None))
            self.assertTrue(inventory.completed_export(out, ["all"]))
            session.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}
            with self.assertRaisesRegex(ValueError, "identity must match"):
                inventory.build(self.root / "wrong-account", from_export=self.source, enrich_iam=True)
            self.assertFalse((self.root / "wrong-account").exists())

    def test_iam_export_paginates_custom_documents_and_aws_metadata_and_retains_denials(self):
        from boto3.session import Session
        from botocore.stub import Stubber
        from datetime import datetime, timezone
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        user = {"UserName": "analyst", "UserId": "AIDASYNTHETICUSER", "Arn": "arn:aws:iam::123456789012:user/analyst", "CreateDate": stamp,
                "GroupList": ["investigators"], "UserPolicyList": [{"PolicyName": "inline", "PolicyDocument": json.dumps(document)}]}
        group = {"GroupName": "investigators", "GroupId": "AGPASYNTHETICGROUP", "Arn": "arn:aws:iam::123456789012:group/investigators", "CreateDate": stamp}
        custom = {"PolicyName": "CaseRead", "Arn": "arn:aws:iam::123456789012:policy/CaseRead", "DefaultVersionId": "v1",
                  "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": json.dumps(document)}]}
        aws = {"PolicyName": "ReadOnlyAccess", "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        for denied in (False, True):
            with self.subTest(denied=denied):
                client = sdk.client("iam")
                session = Mock()
                session.client.side_effect = lambda service, **kwargs: client if service == "iam" else Mock(
                    get_caller_identity=Mock(return_value={"Account": "123456789012"}))
                with Stubber(client) as stub:
                    stub.add_response("get_account_authorization_details", {"UserDetailList": [copy.deepcopy(user)], "IsTruncated": True, "Marker": "second"},
                                      {"Filter": ["User", "Role", "Group", "LocalManagedPolicy"]})
                    if denied:
                        stub.add_client_error("get_account_authorization_details", "AccessDenied", "synthetic denial",
                                              expected_params={"Filter": ["User", "Role", "Group", "LocalManagedPolicy"], "Marker": "second"})
                    else:
                        stub.add_response("get_account_authorization_details", {"GroupDetailList": [group], "Policies": [custom], "IsTruncated": False},
                                          {"Filter": ["User", "Role", "Group", "LocalManagedPolicy"], "Marker": "second"})
                    stub.add_response("list_policies", {"Policies": [], "IsTruncated": True, "Marker": "aws-second"}, {"Scope": "AWS", "OnlyAttached": False})
                    stub.add_response("list_policies", {"Policies": [aws], "IsTruncated": False}, {"Scope": "AWS", "OnlyAttached": False, "Marker": "aws-second"})
                    if denied:
                        stub.add_client_error("list_users", "AccessDenied", "synthetic denial", expected_params={})
                    else:
                        listed = {k: v for k, v in user.items() if k not in ("GroupList", "UserPolicyList")}
                        listed["PasswordLastUsed"] = stamp
                        listed["Path"] = "/"
                        stub.add_response("list_users", {"Users": [], "IsTruncated": True, "Marker": "users-next"}, {})
                        stub.add_response("list_users", {"Users": [listed], "IsTruncated": False}, {"Marker": "users-next"})
                    key = {"UserName": "analyst", "AccessKeyId": "AKIASYNTHETICKEY1", "Status": "Active", "CreateDate": stamp}
                    stub.add_response("list_access_keys", {"AccessKeyMetadata": [key], "IsTruncated": True, "Marker": "keys-next"}, {"UserName": "analyst"})
                    if denied:
                        stub.add_client_error("get_access_key_last_used", "AccessDenied", "synthetic denial", expected_params={"AccessKeyId": key["AccessKeyId"]})
                        stub.add_client_error("list_access_keys", "AccessDenied", "synthetic denial", expected_params={"UserName": "analyst", "Marker": "keys-next"})
                    else:
                        stub.add_response("get_access_key_last_used", {"UserName": "analyst", "AccessKeyLastUsed": {
                            "LastUsedDate": stamp, "ServiceName": "s3", "Region": "ap-southeast-1"}}, {"AccessKeyId": key["AccessKeyId"]})
                        stub.add_response("list_access_keys", {"AccessKeyMetadata": [{**key, "AccessKeyId": "AKIASYNTHETICKEY2", "Status": "Inactive"}], "IsTruncated": False}, {"UserName": "analyst", "Marker": "keys-next"})
                        stub.add_response("get_access_key_last_used", {"UserName": "analyst", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}, {"AccessKeyId": "AKIASYNTHETICKEY2"})
                    device = {"UserName": "analyst", "SerialNumber": "arn:aws:iam::123456789012:mfa/analyst", "EnableDate": stamp}
                    stub.add_response("list_mfa_devices", {"MFADevices": [device], "IsTruncated": True, "Marker": "mfa-next"}, {"UserName": "analyst"})
                    if denied:
                        stub.add_client_error("list_mfa_devices", "AccessDenied", "synthetic denial", expected_params={"UserName": "analyst", "Marker": "mfa-next"})
                        stub.add_client_error("get_login_profile", "AccessDenied", "synthetic denial", expected_params={"UserName": "analyst"})
                    else:
                        stub.add_response("list_mfa_devices", {"MFADevices": [{**device, "SerialNumber": "synthetic-hardware-device"}], "IsTruncated": False}, {"UserName": "analyst", "Marker": "mfa-next"})
                        stub.add_response("get_login_profile", {"LoginProfile": {"UserName": "analyst", "CreateDate": stamp, "PasswordResetRequired": False}}, {"UserName": "analyst"})
                    out = self.root / f"iam-{denied}"
                    source = self.root / "iam-False" if denied else self.source
                    before = {p.relative_to(source): p.read_bytes() for p in (source / "raw").rglob("*") if p.is_file()}
                    with patch.object(inventory.boto3, "Session", return_value=session):
                        self.assertEqual(self.cli("--output", out, "--from-export", source, "--enrich-iam"), 0)
                    stub.assert_no_pending_responses()
                for path, contents in before.items():
                    self.assertEqual((out / path).read_bytes(), contents)
                    self.assertEqual((source / path).read_bytes(), contents)
                report = json.loads((out / "report.json").read_text(encoding="utf-8"))
                iam = report["iam"]
                self.assertEqual(iam["users"][0]["GroupList"], ["investigators"])
                self.assertEqual(iam["aws_managed_policies"], [aws])
                self.assertNotIn("PolicyVersionList", iam["aws_managed_policies"][0])
                self.assertEqual(len(iam["errors"]), 6 if denied else 0)
                self.assertEqual(report["errors"], iam["errors"])
                self.assertTrue((out / iam["raw_directory"] / "get_account_authorization_details" / "account" / "00001.json").is_file())
                activity = iam["users"][0]["activity"]
                self.assertEqual(activity["mfa_status"], "unknown" if denied else "collected")
                self.assertEqual(len(activity["mfa_devices"]), 1 if denied else 2)
                self.assertEqual(activity["mfa_devices"][0], {**device, "EnableDate": str(stamp)})
                self.assertEqual(activity["login_profile_status"], "unknown" if denied else "collected")
                raw = out / iam["raw_directory"]
                self.assertTrue((raw / "list_mfa_devices" / "analyst" / "00001.json").is_file())
                if denied:
                    self.assertNotIn("login_profile", activity)
                    self.assertEqual({e["operation"] for e in iam["errors"]}, {
                        "iam.get_account_authorization_details", "iam.list_users", "iam.list_access_keys",
                        "iam.get_access_key_last_used", "iam.list_mfa_devices", "iam.get_login_profile"})
                else:
                    self.assertEqual(activity["login_profile"], {"UserName": "analyst", "CreateDate": str(stamp), "PasswordResetRequired": False})
                    self.assertTrue((raw / "list_mfa_devices" / "analyst" / "00002.json").is_file())
                    self.assertTrue((raw / "get_login_profile" / "analyst" / "00001.json").is_file())
                self.assertEqual(activity["console_status"], "unknown" if denied else "collected")
                self.assertEqual(activity["access_keys_status"], "unknown" if denied else "collected")
                self.assertEqual(len(activity["access_keys"]), 1 if denied else 2)
                self.assertEqual(activity["access_keys"][0]["last_used_status"], "unknown" if denied else "collected")
                if not denied:
                    self.assertEqual(activity["password_last_used"], "2026-01-01 00:00:00+00:00")
                    self.assertEqual(activity["access_keys"][0]["last_used"]["Region"], "ap-southeast-1")
                    self.assertEqual(activity["access_keys"][1]["Status"], "Inactive")
                    self.assertNotIn("LastUsedDate", activity["access_keys"][1]["last_used"])
                    self.assertEqual(iam["groups"][0]["GroupName"], "investigators")
                    self.assertEqual(iam["policies"][0]["DefaultVersionId"], "v1")
                    self.assertIn("s3:GetObject", str(iam["policies"][0]["PolicyVersionList"][0]["Document"]))
                self.assertTrue(inventory.completed_export(out))

    def test_iam_login_profile_absence_failures_and_recreated_user(self):
        from boto3.session import Session
        from botocore.stub import Stubber
        from datetime import datetime, timezone
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        user = {"UserName": "analyst", "UserId": "AIDASYNTHETICUSER", "Arn": "arn:aws:iam::123456789012:user/analyst",
                "Path": "/", "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        for state in ("NoSuchEntity", "ServiceFailure", "AccessDenied", "recreated"):
            with self.subTest(state=state):
                client = sdk.client("iam")
                session = Mock()
                session.client.return_value = client
                out = self.root / state
                with Stubber(client) as stub:
                    stub.add_response("get_account_authorization_details", {"UserDetailList": [copy.deepcopy(user)], "IsTruncated": False},
                                      {"Filter": ["User", "Role", "Group", "LocalManagedPolicy"]})
                    stub.add_response("list_policies", {"Policies": [], "IsTruncated": False}, {"Scope": "AWS", "OnlyAttached": False})
                    listed = {**user, "UserId": "AIDARECREATEDUSER"} if state == "recreated" else user
                    stub.add_response("list_users", {"Users": [listed], "IsTruncated": False}, {})
                    if state != "recreated":
                        stub.add_response("list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": "analyst"})
                        if state == "NoSuchEntity":
                            stub.add_response("list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": "analyst"})
                        else:
                            stub.add_client_error("list_mfa_devices", state, "synthetic failure", expected_params={"UserName": "analyst"})
                        stub.add_client_error("get_login_profile", state, "synthetic failure", expected_params={"UserName": "analyst"})
                    with redirect_stdout(io.StringIO()):
                        iam = inventory.collect_iam(session, [], out)
                    stub.assert_no_pending_responses()
                activity = iam["users"][0]["activity"]
                self.assertEqual(activity["login_profile_status"], "not_configured" if state == "NoSuchEntity" else "unknown")
                self.assertNotIn("login_profile", activity)
                self.assertEqual(activity["mfa_status"], "collected" if state == "NoSuchEntity" else "unknown")
                self.assertEqual(activity["mfa_devices"], [])
                expected = set() if state == "NoSuchEntity" else {"iam.list_users"} if state == "recreated" else {
                    "iam.list_mfa_devices", "iam.get_login_profile"}
                self.assertEqual({e["operation"] for e in iam["errors"]}, expected)
                if state == "recreated":
                    self.assertEqual(activity["access_keys_status"], "unknown")
                    self.assertFalse((out / iam["raw_directory"] / "list_mfa_devices").exists())

    def test_collector_keeps_partial_pages_and_denied_calls_as_errors(self):
        from botocore.exceptions import ClientError
        client = Mock()
        client.can_paginate.return_value = False
        for operation, key in [("describe_subnets", "Subnets"), ("describe_instances", "Reservations"),
                               ("describe_network_interfaces", "NetworkInterfaces"), ("describe_security_groups", "SecurityGroups"),
                               ("describe_route_tables", "RouteTables"), ("describe_internet_gateways", "InternetGateways"),
                               ("describe_network_acls", "NetworkAcls"), ("describe_db_instances", "DBInstances"),
                               ("describe_db_clusters", "DBClusters"), ("describe_load_balancers", "LoadBalancers"),
                               ("describe_target_groups", "TargetGroups")]:
            getattr(client, operation).return_value = {key: []}
        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic denial"}}, "DescribeVpcs")
        def pages():
            yield {"Vpcs": [{"VpcId": "vpc-test"}]}
            raise denied
        client.can_paginate.side_effect = lambda operation: operation == "describe_vpcs"
        client.get_paginator.return_value.paginate.return_value = pages()
        client.describe_subnets.side_effect = denied
        session = Mock()
        session.client.return_value = client
        with patch.object(inventory.boto3, "Session", return_value=session), redirect_stdout(io.StringIO()):
            region = inventory.collect_region("test-region", None, self.root / "partial")
        self.assertEqual(region["describe_vpcs"], [{"VpcId": "vpc-test"}])
        self.assertEqual({e["operation"] for e in region["errors"]}, {"describe_vpcs", "describe_subnets"})
        self.assertTrue((self.root / "partial" / "raw" / "test-region" / "describe_vpcs" / "00001.json").exists())
        self.assertEqual(analyze({}, [region])["errors"], region["errors"])


if __name__ == "__main__":
    unittest.main()
