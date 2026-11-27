"""Derived historical pod observations from attached EKS logs, never live inventory."""
from itertools import islice
import re

import simplejson as json

from .eks import KIND, ORIGIN, milliseconds


LIMITATIONS = [
    "Historical log observations, not a complete or current pod inventory. No Kubernetes or AWS calls are made.",
    "A conventional EKS log-group name supplies a cluster label, not proof of the current cluster incarnation.",
    "Audit stages are retained separately. A request, API response or exec connection does not prove runtime success.",
    "Missing UIDs leave pod instances unresolved; names can be reused. No pod placement or effective access is inferred.",
    "Authenticated caller pod/node credentials are separate from action targets and are not proof of current placement. SubjectAccessReview spec.extra is not authenticated caller context.",
    "Unrecognized messages and sources without explicit cluster context are not attributed by name, time, IP or VPC guesses.",
    "No matching observations does not mean no pods exist. Collection limits, expiry and missing logs remain coverage gaps.",
]


def text(value):
    return value if isinstance(value, str) and value else None


def pod_fields(message):
    """Keep authenticated caller credentials, target pods and workload metadata separate."""
    if not isinstance(message, dict):
        return []
    if message.get("kind") == "Event" and message.get("apiVersion") == "audit.k8s.io/v1":
        ref = message.get("objectRef") if isinstance(message.get("objectRef"), dict) else {}
        status = message.get("responseStatus")
        code = status.get("code") if isinstance(status, dict) else None
        code = code if type(code) is int else None
        user = message.get("user") if isinstance(message.get("user"), dict) else {}
        common = {"action": text(message.get("verb")), "subresource": text(ref.get("subresource")),
                  "stage": text(message.get("stage")), "status_code": code,
                  "outcome": f"API response {code}" if code is not None else "Outcome not recorded",
                  "actor": text(user.get("username")), "source_type": "Kubernetes audit",
                  "target_resource": text(ref.get("resource")), "target_namespace": text(ref.get("namespace"))}
        rows = []
        extra = user.get("extra") if isinstance(user.get("extra"), dict) else {}
        credentials = {}
        for field, key in (("pod", "pod-name"), ("uid", "pod-uid"), ("node", "node-name"), ("node_uid", "node-uid")):
            values = extra.get("authentication.kubernetes.io/" + key)
            credentials[field] = text(values[0]) if isinstance(values, list) and len(values) == 1 else None
        if credentials["pod"]:
            service_account = re.fullmatch(r"system:serviceaccount:([^:]+):([^:]+)", common["actor"] or "")
            rows.append({**common, **credentials, "observation_role": "Authenticated caller",
                         "namespace": service_account[1] if service_account else None,
                         "namespace_basis": "Service-account username" if service_account else "Not recorded"})
        if ref.get("resource") == "pods":
            response = message.get("responseObject")
            metadata = response.get("metadata", {}) if isinstance(response, dict) and response.get("kind") == "Pod" else {}
            if not isinstance(metadata, dict):
                metadata = {}
            name = text(ref.get("name")) or text(metadata.get("name"))
            namespace = text(ref.get("namespace")) or text(metadata.get("namespace"))
            if name:  # List/watch requests never manufacture named target pods.
                same_response = metadata.get("name") == name and metadata.get("namespace") == namespace
                rows.append({**common, "observation_role": "Target pod", "namespace": namespace,
                             "namespace_basis": "Audit object reference / matching Pod response",
                             "pod": name, "uid": text(ref.get("uid")) or (text(metadata.get("uid")) if same_response else None),
                             "node": None, "node_uid": None})
        return rows
    kubernetes = message.get("kubernetes")
    if isinstance(kubernetes, dict) and text(kubernetes.get("pod_name")):
        return [{"namespace": text(kubernetes.get("namespace_name")),
                "pod": kubernetes["pod_name"], "uid": text(kubernetes.get("pod_id")),
                "observation_role": "Workload metadata", "namespace_basis": "Explicit Kubernetes log metadata",
                "node": None, "node_uid": None, "target_resource": None, "target_namespace": None,
                "action": None, "subresource": None, "stage": None, "status_code": None,
                "outcome": "Workload log observation; outcome not assessed", "actor": None,
                "source_type": "Structured Kubernetes workload log"}]
    return []


def prepare(connection, sources):
    """Stream immutable attached sources once into a disposable, disk-backed TEMP index."""
    columns = {"id": "BIGINT", "record_sha256": "VARCHAR", "dataset_index": "INTEGER", "time": "TIMESTAMPTZ",
               "account": "VARCHAR", "region": "VARCHAR", "cluster": "VARCHAR", "cluster_basis": "VARCHAR",
               **{key: "VARCHAR" for key in ("namespace", "pod", "uid", "action", "subresource", "stage",
                                             "observation_role", "namespace_basis", "node", "node_uid", "target_resource", "target_namespace")},
               "status_code": "INTEGER", "outcome": "VARCHAR", "actor": "VARCHAR", "source_type": "VARCHAR",
               "source": "JSON"}
    datasets, offset = [], 0
    connection.execute("BEGIN TRANSACTION")
    try:
        connection.execute("CREATE TEMP TABLE eks_pod_observations (" + ",".join(f'"{key}" {kind}' for key, kind in columns.items()) + ")")
        connection.execute("CREATE TEMP TABLE eks_pod_log_counts (account VARCHAR, region VARCHAR, cluster VARCHAR, time TIMESTAMPTZ, malformed BOOLEAN, unrecognized BOOLEAN)")
        for index, info in enumerate(sources):
            source_offset = offset
            offset += int(info["records"])
            if info.get("origin") != ORIGIN:
                continue
            dataset = {"dataset_index": index, "origin": info["origin"], "records": info["records"],
                       "source_sha256": info.get("source_sha256"), "manifest": None, "coverage_records": []}
            datasets.append(dataset)
            # Attached evidence catalogs are shared by cursors; the Store's TEMP views are not.
            catalog = "evidence" if index == 0 else f"other_{index - 1}"
            cursor = connection.cursor()
            try:
                cursor.execute(f"SELECT source_record + ?, record_sha256, raw_event->>'$.date', raw_event::VARCHAR FROM {catalog}.raw_events ORDER BY source_record", [source_offset])
                while batch := cursor.fetchmany(500):
                    observations, counts = [], []
                    for record, digest, stamp, raw in batch:
                        content = json.loads(raw, use_decimal=True).get("content")
                        if not isinstance(content, dict):
                            continue
                        if (str(content.get("kind", "")).startswith("EKS collection coverage")
                                or content.get("kind") == KIND and content.get("complete") is True):
                            dataset["coverage_records"].append({"id": record, "record_sha256": digest,
                                                                "time": stamp, "manifest": content})
                            continue
                        if content.get("kind") != "CloudWatch log event":
                            continue
                        event = content.get("event")
                        if not isinstance(event, dict):
                            continue
                        try:
                            message = json.loads(event.get("message", ""), use_decimal=True)
                            malformed = False
                        except (ValueError, TypeError):
                            message, malformed = None, True
                        group = text(content.get("log_group")) or ""
                        conventional = re.fullmatch(r"/aws/eks/([^/]+)/cluster", group)
                        kubernetes = message.get("kubernetes") if isinstance(message, dict) else None
                        cluster = conventional[1] if conventional else (text(kubernetes.get("cluster_name")) if isinstance(kubernetes, dict) else None)
                        fields = pod_fields(message)
                        counts.append((text(content.get("account")), text(content.get("region")), cluster, stamp, malformed, not fields))
                        if not fields or not cluster:
                            continue
                        source = {"log_group": group, "log_stream": text(event.get("logStreamName")),
                                  "event_id": text(event.get("eventId")), "ingestion_time": event.get("ingestionTime"),
                                  "acquired_at": text(content.get("acquired_at"))}
                        for context in fields:
                            row = {"id": record, "record_sha256": digest, "dataset_index": index, "time": stamp,
                                   "account": text(content.get("account")), "region": text(content.get("region")),
                                   "cluster": cluster, "cluster_basis": "EKS log-group cluster label" if conventional else "Explicit kubernetes.cluster_name in workload log",
                                   **context, "source": json.dumps(source, use_decimal=True)}
                            observations.append(tuple(row[key] for key in columns))
                    if observations:
                        connection.executemany("INSERT INTO eks_pod_observations VALUES (" + ",".join("?" for _ in columns) + ")", observations)
                    if counts:
                        connection.executemany("INSERT INTO eks_pod_log_counts VALUES (?,?,?,?,?,?)", counts)
            finally:
                cursor.close()
            if len(dataset["coverage_records"]) == 1:
                dataset["manifest"] = dataset["coverage_records"][0]["manifest"]
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    return datasets


def validate(body):
    options = {"page", "size", "projection", "coverage_page"}
    allowed = {"account", "region", "cluster", "start", "end", "namespace", "pod", "uid", *options}
    if body.keys() - allowed:
        raise ValueError("Unknown pod-observation query fields")
    if body.get("projection", "full") not in ("full", "summary"):
        raise ValueError("Pod projection must be full or summary")
    if type(body.get("size", 50)) is not int or not 1 <= body.get("size", 50) <= 50:
        raise ValueError("Pod size must be an integer from 1 to 50")
    if type(body.get("coverage_page", 1)) is not int or not 1 <= body.get("coverage_page", 1) <= 1000000:
        raise ValueError("coverage_page must be an integer from 1 to 1000000")
    if body.get("projection", "full") == "full" and body.get("coverage_page", 1) != 1:
        raise ValueError("coverage_page requires summary projection")
    scope = {}
    for key in allowed - options:
        value = body.get(key)
        if key in ("account", "region", "cluster") and (not isinstance(value, str) or not value):
            raise ValueError("Pod observations require account, region and cluster")
        if value is not None and (not isinstance(value, str) or len(value) > 2048):
            raise ValueError(f"{key} must be text up to 2048 characters")
        scope[key] = value or None
    page = body.get("page", 1)
    if type(page) is not int or not 1 <= page <= 1000000:
        raise ValueError("page must be a positive integer up to 1000000")
    bounds = {key: milliseconds(scope[key]) for key in ("start", "end") if scope[key]}
    if bounds.get("start") is not None and bounds.get("end") is not None and bounds["start"] >= bounds["end"]:
        raise ValueError("Pod observation start must be before exclusive end")
    return scope, page, bounds


def query(connection, datasets, scope, page, bounds, size=50, summary=False, coverage_page=1):
    conditions, params = ["account=?", "region=?", "cluster=?"], [scope["account"], scope["region"], scope["cluster"]]
    for key, operator in (("start", ">="), ("end", "<")):
        if key in bounds:
            conditions.append(f"epoch_ms(time) {operator} ?")
            params.append(bounds[key])
    log_predicate, log_params = " AND ".join(conditions), list(params)
    for key in ("namespace", "pod", "uid"):
        if scope[key]:
            conditions.append(f'"{key}"=?')
            params.append(scope[key])
    predicate = " AND ".join(conditions)
    total = connection.execute("SELECT count(*) FROM eks_pod_observations WHERE " + predicate, params).fetchone()[0]
    cursor = connection.execute("SELECT * REPLACE(time::VARCHAR AS time) FROM eks_pod_observations WHERE " + predicate + " ORDER BY time DESC, id DESC, observation_role LIMIT ? OFFSET ?", [*params, size, (page - 1) * size])
    data = [dict(zip([column[0] for column in cursor.description], row)) for row in cursor.fetchall()]
    for row in data:
        row["source"] = json.loads(row["source"], use_decimal=True)
    cursor = connection.execute("""SELECT observation_role, namespace, pod, uid, count(*) AS observations,
        min(time)::VARCHAR AS first_seen, max(time)::VARCHAR AS last_seen, count(*) OVER() AS total_contexts
        FROM eks_pod_observations WHERE """ + predicate + """ GROUP BY observation_role, namespace, pod, uid
        ORDER BY max(time) DESC, observation_role, namespace, pod, uid LIMIT ?""", [*params, size if summary else 50])
    contexts = [dict(zip([column[0] for column in cursor.description], row)) for row in cursor.fetchall()]
    total_contexts = contexts[0]["total_contexts"] if contexts else 0
    for context in contexts:
        context.pop("total_contexts")
    logs, malformed, unrecognized, first_log, last_log = connection.execute("SELECT count(*), count(*) FILTER(WHERE malformed), count(*) FILTER(WHERE unrecognized), min(time)::VARCHAR, max(time)::VARCHAR FROM eks_pod_log_counts WHERE " + log_predicate, log_params).fetchone()
    unresolved = connection.execute("SELECT count(*) FROM eks_pod_log_counts WHERE account=? AND region=? AND cluster IS NULL", [scope["account"], scope["region"]]).fetchone()[0]
    result = {"searched": True, "scope": scope, "total": total, "page": page, "page_size": size, "data": data,
            "contexts": contexts, "total_contexts": total_contexts,
            "coverage": {"datasets": datasets, "log_events": logs, "malformed_messages": malformed,
                         "first_log_time": first_log, "last_log_time": last_log,
                         "unrecognized_messages": unrecognized, "unresolved_cluster_events": unresolved,
                         "pod_observations": total, "limitations": LIMITATIONS}}
    if summary:
        coverage = result["coverage"]
        del coverage["datasets"]
        records_total = sum(len(dataset["coverage_records"]) for dataset in datasets)
        records = ((dataset, record) for dataset in datasets for record in dataset["coverage_records"])
        links = []
        for dataset, record in islice(records, (coverage_page - 1) * 10, coverage_page * 10):
            operations = record["manifest"].get("operations")
            warnings = record["manifest"].get("warnings")
            links.append({"dataset_index": dataset["dataset_index"],
                **{key: record[key] for key in ("id", "record_sha256", "time")},
                "operations_total": len(operations) if isinstance(operations, list) else None,
                "operations_with_gaps": sum(not isinstance(op, dict) or op.get("status") != "retrieved" for op in operations) if isinstance(operations, list) else None,
                "warnings_total": len(warnings) if isinstance(warnings, list) else None})
        coverage.update(datasets_total=len(datasets), datasets_without_coverage=sum(not dataset["coverage_records"] for dataset in datasets),
            coverage_records_total=records_total, coverage_records=links, coverage_page=coverage_page,
            coverage_page_size=10, coverage_next_page=coverage_page + 1 if coverage_page * 10 < records_total else None,
            coverage_scope="All attached EKS collections, not filtered to the selected cluster or time. Read coverage records with get_event; missing manifests mean unknown coverage.")
        result.update(next_page=page + 1 if page * size < total else None, response_limit_bytes=24000)
        if len(json.dumps(result, use_decimal=True, ensure_ascii=True).encode("utf-8")) > 24000:
            raise ValueError("Pod response exceeds 24000 bytes; reduce size or narrow filters. For a single oversized observation inspect original evidence via get_event or the browser; nothing was truncated.")
    return result
