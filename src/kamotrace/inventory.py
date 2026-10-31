"""Read-only AWS network export and offline, evidence-linked exposure report."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import csv
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import shutil
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .importer import in_staging, lock_path, publish, sha256, staging, write_lock

CONFIG = Config(retries={"mode": "standard", "max_attempts": 4},
                connect_timeout=10, read_timeout=40)
LIMITATIONS = [
    "Current configuration snapshot of one authenticated account, collected non-atomically across enabled regions; not historical incident-time state.",
    "Allowed means a direct or validated load-balancer path is permitted by exported AWS configuration, NOT a successful connection or a listening service. No active probes are performed.",
    "Restricted means only specified public source ranges have a permitted path. Blocked refers only to modeled direct and forwarding paths, not every proxy, VPN, peering connection or other account.",
    "TCP and UDP paths intersect security-group ingress, longest-prefix subnet routes and ordered network ACL ingress/return rules. Return destination ports assume client ephemeral ports 1024–65535; at least one permitted combination is sufficient.",
    "ICMP, non-TCP/UDP protocols, middlebox routes, prefix-list expansion failures and missing evidence are marked Unknown where relevant. Host firewalls, listening processes, authentication and DNS behavior are not tested.",
    "RDS PubliclyAccessible is evaluated against every DB subnet, not an asserted current ENI placement. Any permitted candidate subnet is reported; failover placement may differ. RDS analysis uses its endpoint TCP port only.",
    "Load balancers are forwarding hops. Listener/rule actions are traced to instance, IP, Lambda and ALB targets. Configured routes are potential matches, not successful traffic: rule priority shadowing, host/path conditions, authentication, rewrites, WAF and application behavior are not executed.",
    "Direct status is separate from via-load-balancer exposure. A private target can be exposed through a public listener. NLBs without frontend SGs have no frontend SG restriction; backend rules still matter. Unhealthy targets are not treated as isolated because load balancers can fail open.",
    "Backend network validation currently verifies same-VPC IPv4 TCP NLB paths with client IP preservation, no frontend SG, local VPC routes and exported SG/ACL evidence. Other modes remain Unknown rather than assumed reachable. Configured Lambda/IP/ALB targets remain visible even without resolved network or invocation permissions.",
    "Internet-facing load balancer addresses are AWS-managed; no public IP is required on their inventory record. Classic LB registrations are displayed, but listener forwarding and propagated exposure are not assessed for classic LBs. WAF, CloudFront, API Gateway and Global Accelerator are outside this inventory.",
    "An allowlisted public source is not necessarily controlled by a trusted party. The exported files contain sensitive infrastructure metadata and are not encrypted by this tool.",
]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str, ensure_ascii=False), encoding="utf-8")


def name_of(item, fallback):
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"] == "Name"), fallback)


def collect_region(region, profile, out):
    session = boto3.Session(profile_name=profile, region_name=region)
    clients = {}
    errors = []
    data = {"region": region}

    def call(service, operation, key, label=None, **params):
        label = label or operation
        rows = []
        client = clients.setdefault(service, session.client(service, config=CONFIG))
        try:
            pages = (client.get_paginator(operation).paginate(**params)
                     if client.can_paginate(operation) else [getattr(client, operation)(**params)])
            for number, page in enumerate(pages, 1):
                write_json(out / "raw" / region / label / f"{number:05}.json", page)
                rows.extend(page.get(key, []))
        except Exception as exc:
            errors.append({"region": region, "operation": label, "error": str(exc)})
        return rows

    for operation, key in [
        ("describe_vpcs", "Vpcs"), ("describe_subnets", "Subnets"),
        ("describe_instances", "Reservations"), ("describe_network_interfaces", "NetworkInterfaces"),
        ("describe_security_groups", "SecurityGroups"), ("describe_route_tables", "RouteTables"),
        ("describe_internet_gateways", "InternetGateways"), ("describe_network_acls", "NetworkAcls"),
    ]:
        data[operation] = call("ec2", operation, key)
    data["describe_db_instances"] = call("rds", "describe_db_instances", "DBInstances")
    data["describe_db_clusters"] = call("rds", "describe_db_clusters", "DBClusters")
    data["load_balancers"] = call("elbv2", "describe_load_balancers", "LoadBalancers", label="elbv2_load_balancers")
    data["classic_load_balancers"] = call("elb", "describe_load_balancers", "LoadBalancerDescriptions", label="classic_load_balancers")
    data["listeners"] = []
    data["listener_rules"] = {}
    data["load_balancer_attributes"] = {}
    data["target_group_attributes"] = {}
    data["lb_tags"] = {}
    data["target_groups"] = call("elbv2", "describe_target_groups", "TargetGroups", label="elbv2_target_groups")
    data["target_health"] = {}
    for lb in data["load_balancers"]:
        arn, label = lb["LoadBalancerArn"], lb["LoadBalancerName"]
        listeners = call("elbv2", "describe_listeners", "Listeners", label="listeners_" + label, LoadBalancerArn=arn)
        data["listeners"].extend(listeners)
        data["load_balancer_attributes"][arn] = call("elbv2", "describe_load_balancer_attributes", "Attributes",
                                                    label="lb_attributes_" + label, LoadBalancerArn=arn)
        data["lb_tags"][arn] = call("elbv2", "describe_tags", "TagDescriptions", label="lb_tags_" + label, ResourceArns=[arn])
        for listener in listeners:
            if lb["Type"] == "application":
                data["listener_rules"][listener["ListenerArn"]] = call(
                    "elbv2", "describe_rules", "Rules", label="rules_" + listener["ListenerArn"].rsplit("/", 1)[-1],
                    ListenerArn=listener["ListenerArn"])
    for tg in data["target_groups"]:
        data["target_health"][tg["TargetGroupArn"]] = call(
            "elbv2", "describe_target_health", "TargetHealthDescriptions",
            label="targets_" + tg["TargetGroupArn"].split("/")[-1], TargetGroupArn=tg["TargetGroupArn"])
        data["target_group_attributes"][tg["TargetGroupArn"]] = call(
            "elbv2", "describe_target_group_attributes", "Attributes",
            label="tg_attributes_" + tg["TargetGroupArn"].split("/")[-1], TargetGroupArn=tg["TargetGroupArn"])
    prefix_ids = {p["PrefixListId"] for sg in data["describe_security_groups"]
                  for perm in sg.get("IpPermissions", []) + sg.get("IpPermissionsEgress", []) for p in perm.get("PrefixListIds", [])}
    prefix_ids.update(r["DestinationPrefixListId"] for table in data["describe_route_tables"]
                      for r in table["Routes"] if "DestinationPrefixListId" in r)
    data["prefix_lists"] = {}
    for pid in sorted(prefix_ids):
        data["prefix_lists"][pid] = call("ec2", "get_managed_prefix_list_entries", "Entries", label=pid, PrefixListId=pid)
    data["errors"] = errors
    write_json(out / "regions" / f"{region}.json", data)
    print(f"{region}: {sum(len(r['Instances']) for r in data['describe_instances'])} EC2, "
          f"{len(data['describe_db_instances'])} RDS, {len(data['load_balancers'])} LB; {len(errors)} errors", flush=True)
    return data


def collect_iam(session, regions, out):
    started = datetime.now(timezone.utc).isoformat()
    arns = sorted({instance["IamInstanceProfile"]["Arn"] for region in regions
                   for reservation in region["describe_instances"] for instance in reservation["Instances"]
                   if instance.get("IamInstanceProfile", {}).get("Arn")})
    client = session.client("iam", config=CONFIG)
    profiles, errors = {}, []
    for arn in arns:
        name = arn.rsplit("/", 1)[-1]
        try:
            response = client.get_instance_profile(InstanceProfileName=name)
            write_json(out / "raw" / "global" / "iam_instance_profiles" / f"{name}.json", response)
            profile = response["InstanceProfile"]
            if profile["Arn"] != arn:
                raise ValueError(f"Returned profile ARN differs from EC2 assignment: {arn}")
            profiles[arn] = {"status": "Resolved", "roles": [{"name": r["RoleName"], "arn": r["Arn"]} for r in profile["Roles"]]}
        except Exception as exc:
            profiles[arn] = {"status": "Unknown", "roles": []}
            errors.append({"region": "global", "operation": "iam.get_instance_profile", "error": f"{arn}: {exc}"})
    result = {"started_at_utc": started, "completed_at_utc": datetime.now(timezone.utc).isoformat(),
              "profiles": profiles, "errors": errors}
    write_json(out / "iam.json", result)
    print(f"IAM: {len(arns)} assigned profiles; {len(errors)} lookup errors", flush=True)
    return result


def intersect(a, b):
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


def subtract(box, cut):
    """Subtract an N-dimensional inclusive integer box, preserving exact residuals."""
    overlap = [intersect(a, b) for a, b in zip(box, cut)]
    if any(x is None for x in overlap):
        return [box]
    result, core = [], list(box)
    for dim, (lo, hi) in enumerate(overlap):
        if core[dim][0] < lo:
            part = core.copy()
            part[dim] = (core[dim][0], lo - 1)
            result.append(tuple(part))
        if hi < core[dim][1]:
            part = core.copy()
            part[dim] = (hi + 1, core[dim][1])
            result.append(tuple(part))
        core[dim] = (lo, hi)
    return result


def net_range(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return (int(net.network_address), int(net.broadcast_address))


def public_ranges(cidr):
    """Exclude non-internet source space, including private, shared and documentation nets."""
    net = ipaddress.ip_network(cidr, strict=False)
    exclusions = (
        ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
         "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
         "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"] if net.version == 4 else
        ["::/3", "4000::/2", "8000::/1", "2001:db8::/32"])
    boxes = [((int(net.network_address), int(net.broadcast_address)),)]
    for excluded in exclusions:
        boxes = [part for box in boxes for part in subtract(box, (net_range(excluded),))]
    return [b[0] for b in boxes]


def apply_acl(boxes, entries, protocol, family, egress, port_dimension=None):
    pending, allowed = list(boxes), []
    for rule in sorted((e for e in entries if e.get("Egress") == egress), key=lambda e: e["RuleNumber"]):
        cidr = rule.get("CidrBlock" if family == 4 else "Ipv6CidrBlock")
        if not cidr or str(rule["Protocol"]) not in ("-1", protocol):
            continue
        ports = rule.get("PortRange", {"From": 0, "To": 65535})
        cut = (net_range(cidr), (0, 65535), (0, 65535))
        cut = list(cut)
        cut[(2 if egress else 1) if port_dimension is None else port_dimension] = (ports["From"], ports["To"])
        residual = []
        for box in pending:
            overlap = tuple(intersect(a, b) for a, b in zip(box, cut))
            if all(x is not None for x in overlap) and rule["RuleAction"] == "allow":
                allowed.append(overlap)
            residual.extend(subtract(box, cut))
        pending = residual
    return allowed


def routed_ranges(source, routes, family, igws):
    pending, allowed, unknown = [(source,)], [], False
    key = "DestinationCidrBlock" if family == 4 else "DestinationIpv6CidrBlock"
    for route in sorted((r for r in routes if key in r), key=lambda r: ipaddress.ip_network(r[key]).prefixlen, reverse=True):
        cut = (net_range(route[key]),)
        for box in pending:
            match = intersect(box[0], cut[0])
            if match and route.get("State", "active") == "active":
                if route.get("GatewayId") in igws:
                    allowed.append((match, route[key] + " → " + route["GatewayId"]))
                elif any(route.get(k) for k in ("NetworkInterfaceId", "InstanceId", "TransitGatewayId", "VpcEndpointId", "CarrierGatewayId", "LocalGatewayId", "CoreNetworkArn")):
                    unknown = True
        pending = [part for box in pending for part in subtract(box, cut)]
    return allowed, unknown


def range_text(bounds, family):
    cls = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    return ", ".join(str(n) for n in ipaddress.summarize_address_range(cls(bounds[0]), cls(bounds[1])))


def assess(resource, region):
    """Evaluate direct paths only; absent dependencies cannot become a safe finding."""
    if resource["state"] in ("stopped", "stopping", "terminated", "shutting-down", "failed"):
        return "Inactive", "Resource is not currently in a serving state.", []
    if not resource["details"]["public_families"]:
        return "Blocked", "No direct public address / public-access setting.", []
    sgs = {s["GroupId"]: s for s in region["describe_security_groups"]}
    group_ids = resource["security_groups"]
    if not group_ids and resource["kind"] == "Load balancer" and resource["details"].get("type") == "network":
        group_ids = ["NLB: no frontend security group"]
        sgs[group_ids[0]] = {"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                              "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}
    tables = region["describe_route_tables"]
    acls = region["describe_network_acls"]
    igws = {g["InternetGatewayId"] for g in region["describe_internet_gateways"]
            if any(a["VpcId"] == resource["vpc_id"] and a["State"] == "available" for a in g.get("Attachments", []))}
    if any(any(a.get("GatewayId") in igws for a in t.get("Associations", []))
           and any(r.get("GatewayId") != "local" for r in t.get("Routes", [])) for t in tables):
        return "Unknown", "Custom internet-gateway ingress routing requires middlebox path analysis.", []
    unknown = resource["details"].get("unsupported", False)
    unknown |= resource["state"] not in ("running", "available", "active")
    failures = {e["operation"] for e in region["errors"]}
    if failures & {"describe_security_groups", "describe_subnets", "describe_route_tables", "describe_network_acls", "describe_internet_gateways"}:
        unknown = True
    if not group_ids or any(s not in sgs for s in group_ids):
        unknown = True
    paths = []
    for subnet_id, families in resource["details"]["public_families"].items():
        table = next((t for t in tables if any(a.get("SubnetId") == subnet_id for a in t.get("Associations", []))), None)
        if table is None:
            table = next((t for t in tables if t["VpcId"] == resource["vpc_id"] and any(a.get("Main") for a in t.get("Associations", []))), None)
        acl = next((a for a in acls if any(s["SubnetId"] == subnet_id for s in a.get("Associations", []))), None)
        if table is None or acl is None or not igws:
            if table is None or acl is None or "describe_internet_gateways" in failures:
                unknown = True
            continue
        routes = []
        unresolved_route_prefix = False
        for route in table["Routes"]:
            pid = route.get("DestinationPrefixListId")
            if not pid:
                routes.append(route)
            elif pid in failures or pid not in region["prefix_lists"]:
                unresolved_route_prefix = True
            else:
                for entry in region["prefix_lists"][pid]:
                    key = "DestinationCidrBlock" if ipaddress.ip_network(entry["Cidr"]).version == 4 else "DestinationIpv6CidrBlock"
                    routes.append({**route, key: entry["Cidr"]})
        if unresolved_route_prefix:
            unknown = True
            continue  # Unknown prefixes could shadow any otherwise permitted return path.
        for sg_id in group_ids:
            for perm in sgs.get(sg_id, {}).get("IpPermissions", []):
                proto = str(perm["IpProtocol"])
                sources = [(r["CidrIp"], None) for r in perm.get("IpRanges", [])]
                sources += [(r["CidrIpv6"], None) for r in perm.get("Ipv6Ranges", [])]
                for prefix in perm.get("PrefixListIds", []):
                    pid = prefix["PrefixListId"]
                    if pid in failures:
                        unknown = True
                    sources += [(e["Cidr"], pid) for e in region["prefix_lists"].get(pid, [])]
                for cidr, prefix in sources:
                    family = ipaddress.ip_network(cidr).version
                    if family not in families or not public_ranges(cidr):
                        continue
                    if proto not in ("-1", "6", "17", "tcp", "udp"):
                        if resource["details"].get("service_ports") is None:
                            unknown = True
                        continue
                    protocols = ["6", "17"] if proto == "-1" else [{"tcp": "6", "udp": "17"}.get(proto, proto)]
                    for protocol in protocols:
                        ports = (0, 65535) if proto == "-1" else (perm["FromPort"], perm["ToPort"])
                        wanted = resource["details"].get("service_ports")
                        port_ranges = [intersect(ports, (p, p)) for pr, p in wanted if pr == protocol] if wanted is not None else [ports]
                        for port_range in filter(None, port_ranges):
                            for source in public_ranges(cidr):
                                routed, middlebox = routed_ranges(source, routes, family, igws)
                                unknown |= middlebox
                                for routed_source, route in routed:
                                    boxes = [(routed_source, port_range, (1024, 65535))]
                                    boxes = apply_acl(boxes, acl["Entries"], protocol, family, False)
                                    boxes = apply_acl(boxes, acl["Entries"], protocol, family, True)
                                    for box in boxes:
                                        paths.append({"family": f"IPv{family}", "protocol": "TCP" if protocol == "6" else "UDP",
                                                      "ports": str(box[1][0]) if box[1][0] == box[1][1] else f"{box[1][0]}–{box[1][1]}",
                                                      "source": range_text(box[0], family), "subnet_id": subnet_id,
                                                      "security_group": sg_id, "route": table["RouteTableId"] + ": " + route,
                                                      "acl": acl["NetworkAclId"], "world_rule": cidr in ("0.0.0.0/0", "::/0"),
                                                      "return_ports": list(box[2]),
                                                      "detail": f"Source rule {cidr}" + (f" ({prefix})" if prefix else "") + f"; ACL permits a return destination port in {box[2][0]}–{box[2][1]}"})
    if paths:
        status = "Allowed" if any(p["world_rule"] for p in paths) else "Restricted"
        summary = "Direct internet path permitted by configuration" + (" from specified public ranges only." if status == "Restricted" else " by a world-source SG rule (see effective sources).")
        if any(p["security_group"] == "NLB: no frontend security group" for p in paths):
            summary = "NLB frontend path permitted without a frontend SG restriction; inspect effective route/ACL sources and separate backend validation."
        if unknown:
            summary += " Additional paths could not be fully evaluated."
        return status, summary, paths
    if unknown:
        return "Unknown", "Insufficient evidence or unsupported routing/protocol; do not treat as isolated.", []
    return "Blocked", "No direct TCP/UDP path permitted by the exported address, route, SG and ACL configuration.", []


def assess_nlb_backend(lb, tg, target, frontend_paths, region):
    """Bounded validation of preserved-client IPv4 TCP NLB flows to a known ENI."""
    attributes = {a["Key"]: a["Value"] for a in region.get("target_group_attributes", {}).get(tg["TargetGroupArn"], [])}
    if (lb.get("Type") != "network" or lb.get("SecurityGroups") or tg.get("Protocol") != "TCP"
            or attributes.get("preserve_client_ip.enabled") != "true"):
        return "Unknown", ["Backend mode is outside preserved-client IPv4 TCP NLB validation; SG/ACL or invocation access is not assumed."]
    instances = [i for r in region["describe_instances"] for i in r["Instances"]]
    instance = next((i for i in instances if i["InstanceId"] == target["Id"]), None)
    ip = instance.get("PrivateIpAddress") if instance else target["Id"]
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError("IPv6")
    except (ValueError, TypeError):
        return "Unknown", ["Target primary IPv4 address is unresolved."]
    eni = next((e for e in region.get("describe_network_interfaces", [])
                if any(p["PrivateIpAddress"] == ip for p in e.get("PrivateIpAddresses", []))), None)
    if not eni or eni.get("VpcId") != lb.get("VpcId"):
        return "Unknown", ["Target ENI is unresolved or outside the NLB VPC; private-network routing is unverified."]
    sgs = {s["GroupId"]: s for s in region["describe_security_groups"]}
    group_ids = [g["GroupId"] for g in eni.get("Groups", [])]
    if not group_ids or any(g not in sgs for g in group_ids):
        return "Unknown", ["Target ENI security group evidence is missing."]
    target_acl = next((a for a in region["describe_network_acls"]
                       if any(s["SubnetId"] == eni["SubnetId"] for s in a.get("Associations", []))), None)
    if not target_acl:
        return "Unknown", ["Target subnet ACL evidence is missing."]

    def local_route(subnet, destination):
        table = next((t for t in region["describe_route_tables"] if any(a.get("SubnetId") == subnet for a in t.get("Associations", []))), None)
        if table is None:
            table = next((t for t in region["describe_route_tables"] if t["VpcId"] == lb["VpcId"] and any(a.get("Main") for a in t.get("Associations", []))), None)
        if not table:
            return False
        routes = []
        for route in table["Routes"]:
            pid = route.get("DestinationPrefixListId")
            if not pid:
                routes.append(route)
            elif pid not in region["prefix_lists"] or any(e["operation"] == pid for e in region["errors"]):
                return False
            else:
                routes.extend({**route, "DestinationCidrBlock": e["Cidr"]} for e in region["prefix_lists"][pid] if ":" not in e["Cidr"])
        matches = [r for r in routes if "DestinationCidrBlock" in r and ipaddress.ip_address(destination) in ipaddress.ip_network(r["DestinationCidrBlock"])]
        best = max(matches, key=lambda r: ipaddress.ip_network(r["DestinationCidrBlock"]).prefixlen, default={})
        return best.get("GatewayId") == "local" and best.get("State", "active") == "active"

    port, permitted, uncertain, world_rule = target.get("Port", tg.get("Port")), [], False, False
    lb_attributes = {a["Key"]: a["Value"] for a in region.get("load_balancer_attributes", {}).get(lb["LoadBalancerArn"], [])}
    cross_zone = attributes.get("load_balancing.cross_zone.enabled", "use_load_balancer_configuration")
    if cross_zone == "use_load_balancer_configuration":
        cross_zone = lb_attributes.get("load_balancing.cross_zone.enabled", "false")
    for front in frontend_paths:
        if front["family"] != "IPv4" or front["protocol"] != "TCP":
            uncertain = True
            continue
        lb_eni = next((e for e in region.get("describe_network_interfaces", [])
                       if e.get("Description") == "ELB " + lb["LoadBalancerArn"].split("loadbalancer/")[-1]
                       and e.get("SubnetId") == front["subnet_id"]), None)
        if not lb_eni:
            uncertain = True
            continue
        if cross_zone != "true" and lb_eni.get("AvailabilityZone") != eni.get("AvailabilityZone"):
            continue
        if not local_route(lb_eni["SubnetId"], ip) or not local_route(eni["SubnetId"], lb_eni["PrivateIpAddress"]):
            uncertain = True
            continue
        lb_acl = next((a for a in region["describe_network_acls"] if a["NetworkAclId"] == front["acl"]), None)
        if not lb_acl:
            uncertain = True
            continue
        for gid in group_ids:
            for rule in sgs[gid].get("IpPermissions", []):
                if str(rule["IpProtocol"]) not in ("-1", "6", "tcp"):
                    continue
                if str(rule["IpProtocol"]) != "-1" and not rule["FromPort"] <= port <= rule["ToPort"]:
                    continue
                cidrs = [r["CidrIp"] for r in rule.get("IpRanges", [])]
                for prefix in rule.get("PrefixListIds", []):
                    pid = prefix["PrefixListId"]
                    if pid not in region["prefix_lists"] or any(e["operation"] == pid for e in region["errors"]):
                        uncertain = True
                    cidrs += [e["Cidr"] for e in region["prefix_lists"].get(pid, []) if ":" not in e["Cidr"]]
                for source in front["source"].split(", "):
                    for cidr in cidrs:
                        common = intersect(net_range(source), net_range(cidr))
                        if common is None:
                            continue
                        # Keep the same client source/return port across both directions.
                        boxes = [(common, (port, port), tuple(front["return_ports"]))]
                        boxes = apply_acl(boxes, target_acl["Entries"], "6", 4, False)
                        boxes = apply_acl(boxes, target_acl["Entries"], "6", 4, True)
                        for box in boxes:
                            backend = [(net_range(ip + "/32"), box[1], box[2])]
                            backend = apply_acl(backend, lb_acl["Entries"], "6", 4, True, 1)
                            backend = apply_acl(backend, lb_acl["Entries"], "6", 4, False, 2)
                            if backend:
                                world_rule |= cidr == "0.0.0.0/0" and front["world_rule"]
                                permitted.append(f"{range_text(box[0], 4)} → {ip}:{port}; {gid}; target {target_acl['NetworkAclId']}; NLB {lb_acl['NetworkAclId']}; local routes; preserved client IP")
    if permitted:
        return "Allowed" if world_rule else "Restricted", sorted(set(permitted))
    return ("Unknown", ["Missing evidence or nonlocal routing prevents full backend validation."]) if uncertain else (
        "Blocked", ["No shared client-source / target-port / ACL-return path survived the exported backend network rules."])


def add_forwarding_paths(report, regions):
    resources = report["resources"]
    report["forwarding_paths"], report["listener_actions"] = [], []
    for resource in resources:
        resource.update(direct_status=resource["status"], indirect_status="None", via_load_balancers=[], forwarding_paths=[])
    for region in regions:
        rn = region["region"]
        by_id = {r["id"]: r for r in resources if r["region"] == rn}
        tgs = {t["TargetGroupArn"]: t for t in region["target_groups"]}
        for lb in region["load_balancers"]:
            lb_resource = by_id[lb["LoadBalancerArn"]]
            for listener in (l for l in region["listeners"] if l["LoadBalancerArn"] == lb["LoadBalancerArn"]):
                rules = region.get("listener_rules", {}).get(listener["ListenerArn"], [])
                if not rules:
                    rules = [{"RuleArn": listener["ListenerArn"] + "/default", "Priority": "default",
                              "Conditions": [], "Actions": listener.get("DefaultActions", [])}]
                for rule in rules:
                    actions = rule.get("Actions", [])
                    base = {"region": rn, "load_balancer_id": lb_resource["id"], "load_balancer_name": lb_resource["name"],
                            "scheme": lb["Scheme"], "listener_id": listener["ListenerArn"], "listener_protocol": listener["Protocol"],
                            "listener_port": listener["Port"], "rule_id": rule["RuleArn"], "priority": rule["Priority"],
                            "conditions": rule.get("Conditions", []), "actions": actions, "transforms": rule.get("Transforms", [])}
                    forwards = [a for a in actions if a["Type"] == "forward"]
                    if not forwards:
                        report["listener_actions"].append({**base, "reason": "No backend forwarding: " + ", ".join(a["Type"] for a in actions)})
                    for action in forwards:
                        groups = action.get("ForwardConfig", {}).get("TargetGroups", []) or [{"TargetGroupArn": action.get("TargetGroupArn"), "Weight": 1}]
                        for group in groups:
                            tg_id = group.get("TargetGroupArn")
                            tg = tgs.get(tg_id, {})
                            entries = region["target_health"].get(tg_id, [])
                            for entry in entries or [{"Target": {"Id": ""}, "TargetHealth": {"State": "empty"}}]:
                                target = entry["Target"]
                                target_id = target["Id"]
                                matches = [r for r in resources if r["id"] == target_id]
                                if not matches:
                                    matches = [r for r in resources if target_id and target_id in r["addresses"]]
                                    local = [r for r in matches if r["region"] == rn and r["vpc_id"] == tg.get("VpcId")]
                                    matches = local or matches
                                backend = matches[0] if len(matches) == 1 else None
                                if target_id and backend is None:
                                    eni = next((e for e in region.get("describe_network_interfaces", [])
                                                if any(p["PrivateIpAddress"] == target_id for p in e.get("PrivateIpAddresses", []))), None)
                                    identifier = target_id if target_id.startswith("arn:") else rn + ":" + tg.get("VpcId", "unknown") + ":target:" + target_id
                                    backend = next((r for r in resources if r["id"] == identifier), None)
                                    if backend is None:
                                        kind = "Lambda" if tg.get("TargetType") == "lambda" else "IP target" if tg.get("TargetType") == "ip" else "Unresolved target"
                                        backend = dict(id=identifier, name=target_id.split(":function:")[-1] if kind == "Lambda" else target_id,
                                            kind=kind, region=rn, vpc_id=eni.get("VpcId", "") if eni else tg.get("VpcId", ""),
                                            subnet_ids=[eni["SubnetId"]] if eni else [], state="registered", addresses=[target_id],
                                            security_groups=[g["GroupId"] for g in eni.get("Groups", [])] if eni else [],
                                            status="Unknown", direct_status="Unknown", indirect_status="None", via_load_balancers=[], forwarding_paths=[],
                                            summary="Registered LB target; direct exposure outside the original EC2/RDS/LB inventory is not assessed.", paths=[],
                                            iam_instance_profile="", iam_roles=[], iam_role_arns=[], iam_role_status="Not applicable",
                                            details={"target_type": tg.get("TargetType"), "eni": eni})
                                        resources.append(backend)
                                port = target.get("Port", tg.get("Port"))
                                protocol = "UDP" if listener["Protocol"] == "UDP" else "TCP"
                                front_paths = [p for p in lb_resource["paths"] if p["ports"] == str(listener["Port"]) and p["protocol"] == protocol]
                                frontend = ("Allowed" if any(p["world_rule"] for p in front_paths) else "Restricted") if front_paths else (
                                    "Blocked" if lb_resource["direct_status"] in ("Allowed", "Restricted", "Blocked") else lb_resource["direct_status"])
                                network, evidence = assess_nlb_backend(lb, tg, target, front_paths, region) if tg and target_id and front_paths else (
                                    "Unknown", ["No directly permitted frontend path, target evidence missing, or upstream LB routing must be evaluated."])
                                health = entry["TargetHealth"]["State"]
                                weight = group.get("Weight", 1)
                                inactive = not target_id or weight == 0 or health in ("unused", "draining") or (backend and backend["direct_status"] == "Inactive")
                                status = "Inactive" if inactive else "Blocked" if network == "Blocked" else "Configured"
                                reason = ("No registered targets / zero traffic weight / target not active for new flows." if inactive else
                                          "Forwarding action references this target; conditions, priority and health remain relevant. Unhealthy is not assumed isolated (fail-open is possible).")
                                if not tg or any(e["operation"] == "targets_" + str(tg_id).split("/")[-1] for e in region["errors"]):
                                    status, reason = "Unknown", "Target group/target collection is incomplete; an empty result is not isolation evidence."
                                row = {**base, "id": f"route-{len(report['forwarding_paths']) + 1}",
                                       "target_group_id": tg_id, "target_group_name": tg.get("TargetGroupName", tg_id),
                                       "target_type": tg.get("TargetType", "unknown"), "target_id": target_id,
                                       "target_resource_id": backend["id"] if backend else "", "target_name": backend["name"] if backend else "(no registered targets)",
                                       "target_resource_region": backend["region"] if backend else "",
                                       "target_port": port, "health": health, "weight": weight,
                                       "frontend_status": frontend, "network_status": network, "status": status,
                                       "reason": reason, "network_evidence": evidence, "public_entry": False}
                                report["forwarding_paths"].append(row)
                                lb_resource["forwarding_paths"].append(row)
                                if backend:
                                    backend["forwarding_paths"].append(row)
    # Reachability propagates only along configured, nonzero forwarding actions.
    # Track listener ports, not just LB identities: exposing :443 must not expose :8443.
    reachable = {(r["load_balancer_id"], r["listener_port"]) for r in report["forwarding_paths"]
                 if r["scheme"] == "internet-facing" and r["frontend_status"] in ("Allowed", "Restricted", "Unknown")}
    while True:
        reached = set(reachable)
        for row in report["forwarding_paths"]:
            if (row["load_balancer_id"], row["listener_port"]) not in reachable or row["status"] not in ("Configured", "Unknown"):
                continue
            row["public_entry"] = True
            target = next((r for r in resources if r["id"] == row["target_resource_id"]), None)
            if target:
                target["indirect_status"] = "Configured" if row["status"] == "Configured" else "Unknown"
                if row["load_balancer_name"] not in target["via_load_balancers"]:
                    target["via_load_balancers"].append(row["load_balancer_name"])
                if target["direct_status"] not in ("Allowed", "Restricted", "Inactive"):
                    candidate = "Unknown"
                    if row["network_status"] in ("Allowed", "Restricted") and row["frontend_status"] in ("Allowed", "Restricted"):
                        candidate = "Allowed" if row["network_status"] == row["frontend_status"] == "Allowed" else "Restricted"
                    rank = ["Allowed", "Restricted", "Unknown", "Blocked"]
                    target["status"] = min((candidate, target["status"]), key=rank.index)
                    target["summary"] = "Internet exposure through a load-balancer forwarding route. " + row["reason"]
                if target["kind"] == "Load balancer":
                    reached.add((target["id"], row["target_port"]))
        if reached == reachable:
            break
        reachable = reached
    report["relationships"] += [{"source": r["load_balancer_id"], "target": r["target_resource_id"], "type": "forwarding",
        "forwarding_path_id": r["id"], "status": r["status"], "public_entry": r["public_entry"],
        "label": f"{r['listener_protocol']}:{r['listener_port']} → {r['target_port'] or r['target_type']}; {r['health']}; {r['status']}"}
        for r in report["forwarding_paths"] if r["target_resource_id"]]


def analyze(metadata, regions, iam=None):
    iam = iam or {"profiles": {}, "errors": []}
    report = {"metadata": {**metadata, "limitations": LIMITATIONS}, "errors": list(iam["errors"]), "resources": [], "vpcs": [], "security_groups": [], "relationships": []}
    if iam.get("completed_at_utc"):
        report["metadata"]["iam_completed_at_utc"] = iam["completed_at_utc"]
    for region in regions:
        rn = region["region"]
        report["errors"].extend(region["errors"])
        report["vpcs"].extend({"id": v["VpcId"], "name": name_of(v, v["VpcId"]), "region": rn,
                               "cidr": ", ".join(a["CidrBlock"] for a in v.get("CidrBlockAssociationSet", []))}
                              for v in region["describe_vpcs"])
        resources = []

        def add(identifier, name, kind, vpc, subnets, state, addresses, groups, details):
            r = dict(id=identifier, name=name, kind=kind, region=rn, vpc_id=vpc, subnet_ids=subnets,
                     state=state, addresses=addresses, security_groups=groups, details=details,
                     iam_instance_profile="", iam_roles=[], iam_role_arns=[], iam_role_status="Not applicable")
            r["status"], r["summary"], r["paths"] = assess(r, region)
            if r["status"] == "Unknown" and kind == "Load balancer" and details.get("type") == "network" and not groups:
                r["summary"] = "Internet-facing NLB without frontend security groups; listeners and targets exported, but end-to-end target access is unverified."
            resources.append(r)
            return r

        for reservation in region["describe_instances"]:
            for instance in reservation["Instances"]:
                families, addresses = {}, []
                groups = {g["GroupId"] for g in instance.get("SecurityGroups", [])}
                for eni in instance.get("NetworkInterfaces", []):
                    fs = []
                    addresses.extend(p["PrivateIpAddress"] for p in eni.get("PrivateIpAddresses", []))
                    public = [p["Association"]["PublicIp"] for p in eni.get("PrivateIpAddresses", []) if p.get("Association", {}).get("PublicIp")]
                    if eni.get("Association", {}).get("PublicIp"):
                        public.append(eni["Association"]["PublicIp"])
                    if public:
                        fs.append(4)
                        addresses.extend(public)
                    ipv6 = [a["Ipv6Address"] for a in eni.get("Ipv6Addresses", []) if ipaddress.ip_address(a["Ipv6Address"]).is_global]
                    if ipv6 and not eni.get("DenyAllIgwTraffic", False):
                        fs.append(6)
                        addresses.extend(ipv6)
                    # Analyze each interface separately: SGs must never bleed between ENIs.
                    if fs:
                        families[eni["NetworkInterfaceId"]] = (eni["SubnetId"], fs, [g["GroupId"] for g in eni.get("Groups", [])])
                    groups.update(g["GroupId"] for g in eni.get("Groups", []))
                r = add(instance["InstanceId"], name_of(instance, instance["InstanceId"]), "EC2", instance.get("VpcId", ""),
                        sorted({e["SubnetId"] for e in instance.get("NetworkInterfaces", [])}), instance["State"]["Name"],
                        sorted(set(addresses)), sorted(groups), {"public_families": {}, "instance_type": instance["InstanceType"],
                        "image_id": instance["ImageId"], "launch_time": instance.get("LaunchTime"), "tags": instance.get("Tags", [])})
                profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
                profile = iam["profiles"].get(profile_arn, {"status": "Unknown", "roles": []})
                r.update(iam_instance_profile=profile_arn, iam_roles=[role["name"] for role in profile["roles"]],
                         iam_role_arns=[role["arn"] for role in profile["roles"]],
                         iam_role_status=profile["status"] if profile_arn else "None assigned")
                findings = []
                for eni_id, (subnet, fs, eni_groups) in families.items():
                    probe = {**r, "security_groups": eni_groups, "details": {"public_families": {subnet: fs}}}
                    status, summary, paths = assess(probe, region)
                    for path in paths:
                        path["detail"] += f"; interface {eni_id}"
                    findings.append((status, summary, paths))
                if findings:
                    best = min(findings, key=lambda f: ["Allowed", "Restricted", "Unknown", "Inactive", "Blocked"].index(f[0]))
                    r["status"], r["summary"] = best[:2]
                    r["paths"] = [p for f in findings for p in f[2]]
                    r["details"]["public_families"] = {sub: fs for sub, fs, _ in families.values()}
        for db in region["describe_db_instances"]:
            subnets = [s["SubnetIdentifier"] for s in db.get("DBSubnetGroup", {}).get("Subnets", [])]
            endpoint = db.get("Endpoint", {})
            public = db.get("PubliclyAccessible", False)
            families = [4, 6] if db.get("NetworkType") == "DUAL" else [4]
            add(db["DBInstanceIdentifier"], db["DBInstanceIdentifier"], "RDS", db.get("DBSubnetGroup", {}).get("VpcId", ""),
                subnets, db["DBInstanceStatus"], [endpoint["Address"]] if endpoint.get("Address") else [],
                [s["VpcSecurityGroupId"] for s in db.get("VpcSecurityGroups", [])],
                {"public_families": {s: families for s in subnets} if public else {},
                 "publicly_accessible": public, "service_ports": [("6", endpoint["Port"])] if "Port" in endpoint else [],
                 "engine": db["Engine"], "engine_version": db["EngineVersion"], "instance_class": db["DBInstanceClass"],
                 "cluster": db.get("DBClusterIdentifier"), "multi_az": db.get("MultiAZ"), "endpoint": endpoint})
        for cluster in region["describe_db_clusters"]:
            if cluster.get("DBClusterMembers"):
                continue  # Member instances already represent Aurora network access.
            sgname = cluster.get("DBSubnetGroup")
            # Cluster-only modes lack instance-level placement/public evidence in this export.
            add(cluster["DBClusterIdentifier"], cluster["DBClusterIdentifier"], "RDS", "", [],
                cluster["Status"], [cluster["Endpoint"]] if cluster.get("Endpoint") else [],
                [s["VpcSecurityGroupId"] for s in cluster.get("VpcSecurityGroups", [])],
                {"public_families": {"unresolved-subnet": [4, 6]}, "unsupported": True, "db_subnet_group": sgname,
                 "engine": cluster["Engine"], "note": "Cluster without instance members; placement requires further evidence."})
        for lb in region["load_balancers"]:
            subnets = [z["SubnetId"] for z in lb["AvailabilityZones"]]
            listeners = [l for l in region["listeners"] if l["LoadBalancerArn"] == lb["LoadBalancerArn"]]
            protocols = {"HTTP": "6", "HTTPS": "6", "TCP": "6", "TLS": "6", "UDP": "17"}
            service_ports = [(protocols[l["Protocol"]], l["Port"]) for l in listeners if l["Protocol"] in protocols]
            service_ports += [(p, l["Port"]) for l in listeners if l["Protocol"] == "TCP_UDP" for p in ("6", "17")]
            public = lb["Scheme"] == "internet-facing"
            families = [4, 6] if lb.get("IpAddressType", "").startswith("dualstack") else [4]
            if lb.get("IpAddressType") == "dualstack-without-public-ipv4":
                families = [6]
            aliases = [e["PrivateIpAddress"] for e in region.get("describe_network_interfaces", [])
                       if e.get("Description") == "ELB " + lb["LoadBalancerArn"].split("loadbalancer/")[-1]]
            add(lb["LoadBalancerArn"], lb["LoadBalancerName"], "Load balancer", lb["VpcId"], subnets, lb["State"]["Code"],
                [lb["DNSName"], *aliases], lb.get("SecurityGroups", []), {"public_families": {s: families for s in subnets} if public else {},
                "scheme": lb["Scheme"], "type": lb["Type"], "service_ports": service_ports, "listeners": listeners,
                "attributes": region.get("load_balancer_attributes", {}).get(lb["LoadBalancerArn"], []),
                "tags": region.get("lb_tags", {}).get(lb["LoadBalancerArn"], []),
                "unsupported": not listeners or any(l["Protocol"] not in (*protocols, "TCP_UDP") for l in listeners)})
        for lb in region["classic_load_balancers"]:
            add(lb["LoadBalancerName"], lb["LoadBalancerName"], "Load balancer", lb.get("VPCId", ""), lb.get("Subnets", []),
                "active", [lb["DNSName"]], lb.get("SecurityGroups", []),
                {"public_families": {s: [4] for s in lb.get("Subnets", [])} if lb.get("Scheme") == "internet-facing" else {},
                 "unsupported": True, "service_ports": [], "listeners": lb.get("ListenerDescriptions", []), "type": "classic"})
            for target in lb.get("Instances", []):
                report["relationships"].append({"source": lb["LoadBalancerName"], "target": target["InstanceId"], "label": "Registered target; path not verified"})
        report["resources"].extend(resources)
        for sg in region["describe_security_groups"]:
            report["security_groups"].append({"id": sg["GroupId"], "name": sg["GroupName"], "region": rn, "vpc_id": sg["VpcId"],
                "ingress": sg.get("IpPermissions", []), "egress": sg.get("IpPermissionsEgress", []),
                "resources": [r["id"] for r in resources if sg["GroupId"] in r["security_groups"]]})
    add_forwarding_paths(report, regions)
    for sg in report["security_groups"]:
        sg["resources"] = [r["id"] for r in report["resources"] if r["region"] == sg["region"] and sg["id"] in r["security_groups"]]
    from collections import Counter
    report["counts"] = dict(Counter(r["status"] for r in report["resources"]))
    return report


def render(out, report):
    write_json(out / "report.json", report)
    columns = ["region", "kind", "id", "name", "state", "vpc_id", "subnet_ids", "addresses", "security_groups",
               "iam_instance_profile", "iam_roles", "iam_role_arns", "iam_role_status", "direct_status", "indirect_status", "via_load_balancers", "status", "summary"]
    with (out / "systems.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for r in report["resources"]:
            row = {k: "; ".join(r[k]) if isinstance(r[k], list) else r[k] for k in columns}
            writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v for k, v in row.items()})
    pathcols = ["resource_id", "region", "status", "family", "protocol", "ports", "source", "subnet_id", "security_group", "route", "acl", "detail"]
    with (out / "internet-paths.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=pathcols, extrasaction="ignore")
        writer.writeheader()
        for r in report["resources"]:
            for p in r["paths"]:
                writer.writerow({**p, "resource_id": r["id"], "region": r["region"], "status": r["status"]})
    with (out / "security-groups.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=["region", "id", "name", "vpc_id", "resources", "ingress", "egress"])
        writer.writeheader()
        for sg in report["security_groups"]:
            writer.writerow({k: json.dumps(v) if isinstance(v, list) else v for k, v in sg.items()})
    with (out / "vpcs.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=["region", "id", "name", "cidr"])
        writer.writeheader()
        writer.writerows(report["vpcs"])
    for filename, rows in [("load-balancer-routes.csv", report["forwarding_paths"]), ("listener-actions.csv", report["listener_actions"])]:
        with (out / filename).open("w", newline="", encoding="utf-8-sig") as stream:
            fields = list(dict.fromkeys(k for row in rows for k in row)) or ["region", "load_balancer_id"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v for k, v in row.items()})


def read_export(folder):
    """Load original standalone exports too; offline loading never constructs an AWS session."""
    folder = Path(folder)
    metadata = json.loads((folder / "collection.json").read_text(encoding="utf-8"))
    regions = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((folder / "regions").glob("*.json"))]
    if (not metadata.get("completed_at_utc") or not metadata.get("account") or not regions
            or sorted(r["region"] for r in regions) != sorted(metadata.get("regions", []))):
        raise ValueError(f"{folder}: incomplete inventory collection or region scope mismatch")
    iam = json.loads((folder / "iam.json").read_text(encoding="utf-8")) if (folder / "iam.json").is_file() else None
    return metadata, regions, iam


def completed_export(folder, regions=None, profile=None):
    """Verify a published KamoTrace snapshot and its exact requested scope, without AWS calls.

    Completion means every selected collector finished, NOT that every API call succeeded.
    Denials and partial API pagination remain visible in report.errors.
    """
    folder = Path(folder)
    try:
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        if (manifest.get("kind") != "kamotrace-inventory" or manifest.get("schema_version") != 1
                or not manifest.get("complete") or not manifest.get("analyzed")):
            return None
        if regions is not None and manifest.get("scope") != {"regions": sorted(set(regions)), "profile": profile}:
            return None
        files = manifest["files"]
        if not {"collection.json", "report.json"}.issubset({f["path"] for f in files}):
            return None
        actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file() and p != folder / "manifest.json"}
        if actual != {f["path"] for f in files}:
            return None
        for item in files:
            path = (folder / item["path"]).resolve()
            if not path.is_relative_to(folder.resolve()) or not path.is_file() or path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"]:
                return None
        read_export(folder)
        report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
        if not all(key in report for key in ("resources", "vpcs", "security_groups", "relationships", "forwarding_paths", "listener_actions", "counts", "metadata", "errors")):
            return None
        return manifest
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def build(output, profile=None, regions=None, from_export=None, enrich_iam=False, collect_only=False, lock=True):
    """Publish a new snapshot directory atomically; never mutate an existing export or input.

    Offline derivations copy raw JSON byte-for-byte and retain the original collection metadata.
    IAM enrichment, when explicitly requested, is separately timestamped by collect_iam.
    """
    output = Path(output).resolve()
    regions = regions or ["all"]
    source = Path(from_export).resolve() if from_export else None
    if in_staging(output) or (source and in_staging(source)):
        raise ValueError("Inventory paths must not be inside a KamoTrace staging folder")
    if source and (output == source or source.is_relative_to(output) or output.is_relative_to(source)
                   or lock_path(output).is_relative_to(source)):
        raise ValueError("Inventory output and its lock must be separate from the original export")
    with write_lock(output) if lock else nullcontext():
        if output.exists():
            raise FileExistsError(f"{output} already exists; use a new output folder (original exports are never overwritten)")
        with staging(output) as staged:
            out = staged.parent / "snapshot"
            out.mkdir()
            if source:
                metadata, data, iam = read_export(source)
                # Copy only original collection inputs, never stale reports or arbitrary export files.
                for name in ("collection.json", "iam.json", "regions", "raw"):
                    path = source / name
                    if path.exists():
                        if path.is_dir():
                            shutil.copytree(path, out / name)
                        else:
                            shutil.copy2(path, out / name)
            else:
                now = datetime.now(timezone.utc)
                session = boto3.Session(profile_name=profile)
                identity = session.client("sts", config=CONFIG).get_caller_identity()
                available = session.client("ec2", config=CONFIG).describe_regions(AllRegions=True)["Regions"]
                enabled = sorted(r["RegionName"] for r in available if r.get("OptInStatus") != "not-opted-in")
                selected = enabled if regions == ["all"] else sorted(set(regions))
                if not selected or set(selected) - set(enabled):
                    raise ValueError("Requested regions must be enabled in the authenticated account; use all alone")
                metadata = {"account": identity["Account"], "identity": identity, "started_at_utc": now.isoformat(),
                            "regions": selected, "region_inventory": available, "limitations": LIMITATIONS}
                write_json(out / "collection.json", metadata)
                with ThreadPoolExecutor(max_workers=6) as pool:
                    data = list(pool.map(lambda rn: collect_region(rn, profile, out), selected))
                metadata["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
                write_json(out / "collection.json", metadata)
                iam = collect_iam(session, data, out)
            if source and enrich_iam:
                session = boto3.Session(profile_name=profile)
                if session.client("sts", config=CONFIG).get_caller_identity()["Account"] != metadata["account"]:
                    raise ValueError("IAM enrichment identity must match the exported account")
                iam = collect_iam(session, data, out)
            if not collect_only:
                render(out, analyze(metadata, data, iam))
            write_json(out / "manifest.json", {
                "kind": "kamotrace-inventory", "schema_version": 1, "complete": True,
                "analyzed": not collect_only, "scope": {"regions": sorted(set(regions)), "profile": profile},
                "from_export": str(source) if source else None,
                "files": [{"path": p.relative_to(out).as_posix(), "sha256": sha256(p), "bytes": p.stat().st_size}
                          for p in sorted(out.rglob("*")) if p.is_file()]})
            publish(out, output)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace inventory", description=__doc__)
    parser.add_argument("--profile")
    parser.add_argument("--regions", nargs="+", default=["all"], help="Enabled regions (default: all)")
    parser.add_argument("--output", type=Path, required=True, help="New output folder; never overwritten")
    parser.add_argument("--from-export", type=Path, help="Reanalyze saved JSON, without AWS calls")
    parser.add_argument("--enrich-iam", action="store_true", help="With --from-export, make read-only IAM calls to resolve assigned profiles")
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        out = build(args.output, args.profile, args.regions, args.from_export, args.enrich_iam, args.collect_only)
        print(f"Inventory snapshot: {out}", flush=True)
        return 0
    except (BotoCoreError, ClientError, OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"kamotrace inventory: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("kamotrace inventory interrupted; no partial snapshot was published", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
