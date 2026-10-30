"""Read local SSM evidence and join commands, system invocations and plugin outputs."""
import hashlib
import json

from .server import parse_time


class Commands:
    def __init__(self, path, connection):
        self.commands, self.events = {}, {}
        self.path = path
        document = json.loads(path.read_text(encoding="utf-8")) if path else {}
        if path and (not isinstance(document, dict) or not isinstance(document.get("account_id"), str)
                     or any(not isinstance(document.get(k), list) for k in ("commands", "invocations", "invocation_details"))):
            raise ValueError("Expected an SSM command/session activity export with account_id, commands, invocations and invocation_details")
        self.limitations = document.get("coverage", {}).get("limitations", [])
        account = document.get("account_id", "")

        def command(region, record):
            key = json.dumps([account, region, record["CommandId"]], separators=(",", ":"))
            return self.commands.setdefault(key, {"key": key, "account": account, "region": region,
                "command_id": record["CommandId"], "record": None, "base64_enrichment": [],
                "systems": {}, "events": []})

        for item in document.get("commands", []):
            entry = command(item["region"], item["record"])
            entry["record"] = item["record"]
            entry["base64_enrichment"] = item.get("base64_enrichment", [])
        for kind in ("invocations", "invocation_details"):
            for item in document.get(kind, []):
                record = item["record"]
                entry = command(item["region"], record)
                system = entry["systems"].setdefault(record["InstanceId"], {
                    "instance_id": record["InstanceId"], "invocation": None, "details": []})
                if kind == "invocations":
                    system["invocation"] = record
                else:
                    system["details"].append(record)
        for entry in self.commands.values():
            for instance in (entry["record"] or {}).get("InstanceIds", []):
                entry["systems"].setdefault(instance, {"instance_id": instance, "invocation": None, "details": []})
            record = entry["record"] or next((s["invocation"] for s in entry["systems"].values() if s["invocation"]), {})
            stamp = record.get("RequestedDateTime")
            entry.update(requested=stamp, requested_ms=int(parse_time(stamp).timestamp() * 1000) if stamp else None,
                document=record.get("DocumentName", ""), status=record.get("Status", "Unknown"),
                target_count=record.get("TargetCount"), systems=list(entry["systems"].values()))

        local = connection.execute("""SELECT source_record, raw_event::VARCHAR, record_sha256
            FROM events WHERE event_source='ssm.amazonaws.com'""").fetchall() if self.commands else []
        sources = [(None, json.dumps(e, ensure_ascii=False), None) for e in document.get("cloudtrail_records", [])]
        sources.extend(local)  # Prefer original evidence JSON when both exports contain the event.
        for source_record, raw, record_hash in sources:
            event = json.loads(raw)
            if event.get("eventSource") != "ssm.amazonaws.com":
                continue
            request, response = event.get("requestParameters") or {}, event.get("responseElements") or {}
            command_id = request.get("commandId") or (response.get("command") or {}).get("commandId")
            key = json.dumps([event.get("recipientAccountId", ""), event.get("awsRegion", ""), command_id], separators=(",", ":"))
            if key not in self.commands:
                continue
            event_key = hashlib.sha256(json.dumps([event.get("recipientAccountId"), event.get("awsRegion"), event.get("eventID")]).encode()).hexdigest()
            self.events[event_key] = {"key": event_key, "event_id": event.get("eventID"),
                "id": source_record, "raw_json": raw, "record_sha256": record_hash,
                "event_time": event.get("eventTime"), "operation": event.get("eventName"),
                "identity": (event.get("userIdentity") or {}).get("arn", ""),
                "source_ip": event.get("sourceIPAddress"), "error": event.get("errorCode"),
                "command_key": key, "source": "DuckDB" if source_record is not None else "Supplemental SSM export"}
        connection.execute("CREATE TEMP TABLE ssm_links(command_key VARCHAR, source_record BIGINT)")
        links = []
        for event in self.events.values():
            self.commands[event["command_key"]]["events"].append({k: v for k, v in event.items() if k != "raw_json"})
            if event["id"] is not None:
                links.append((event["command_key"], event["id"]))
        if links:
            connection.executemany("INSERT INTO ssm_links VALUES (?,?)", links)
        for entry in self.commands.values():
            entry["events"].sort(key=lambda e: (e["event_time"] or "", e["key"]))
            entry["search"] = json.dumps(entry, ensure_ascii=False).lower()
        self.sheet_rows = []
        for entry in self.commands.values():
            decoded = []

            def decoding(items, label):
                for item in items:
                    decoded.append(f"{label} [{item.get('status', 'unknown')}]:\n"
                                   + str(item.get("decoded_text", item.get("error", "Non-text bytes"))))
                    decoding(item.get("nested_decodings", []), label + " / nested")

            for parameter in entry["base64_enrichment"]:
                decoding(parameter.get("decodings", []), f"{parameter['parameter']}[{parameter['value_index']}]")
            base = {k: entry[k] for k in ("key", "command_id", "account", "region", "requested_ms", "document")}
            parameters = (entry["record"] or {}).get("Parameters")
            base.update(parameters="\n\n".join(name + ":\n" + ("\n".join(values) if isinstance(values, list) else str(values))
                                               for name, values in parameters.items()) if parameters is not None else None,
                        decoded="\n\n".join(decoded), events=len(entry["events"]))
            for system in entry["systems"] or [{"instance_id": None, "invocation": None, "details": []}]:
                invocation = system["invocation"] or {}
                plugins = {p["Name"]: p for p in invocation.get("CommandPlugins", [])}
                outputs = [(d["PluginName"], d, False) for d in system["details"]]
                detailed = {name for name, _, _ in outputs}
                outputs.extend((name, plugin, True) for name, plugin in plugins.items() if name not in detailed)
                for name, output, combined in outputs or [(None, {}, False)]:
                    self.sheet_rows.append({**base, "row_id": len(self.sheet_rows), "instance_id": system["instance_id"],
                        "plugin": name, "status": output.get("Status", invocation.get("Status", "Unknown")),
                        "response_code": output.get("ResponseCode"),
                        "stdout": output.get("StandardOutputContent"), "stderr": output.get("StandardErrorContent"),
                        "combined_output": output.get("Output") if combined else None,
                        "output_state": "Combined only" if combined else "Separate streams" if output else "No output collected"})

    def matching(self, body):
        search = body.get("search", "")
        if not isinstance(search, str) or len(search) > 2000:
            raise ValueError("Search must be text up to 2,000 characters")
        start = parse_time(body["start"]).timestamp() * 1000 if body.get("start") else None
        end = parse_time(body["end"]).timestamp() * 1000 if body.get("end") else None
        if start is not None and end is not None and start >= end:
            raise ValueError("Start must be before end")
        return [e for e in self.commands.values() if search.lower() in e["search"]
                and (start is None or e["requested_ms"] is not None and e["requested_ms"] >= start)
                and (end is None or e["requested_ms"] is not None and e["requested_ms"] < end)]

    def list(self, body):
        rows = self.matching(body)
        sort = body.get("sort", "requested_ms")
        if sort not in ("requested_ms", "command_id", "region", "document", "status") or body.get("direction", "desc") not in ("asc", "desc"):
            raise ValueError("Unknown command sort")
        rows.sort(key=lambda e: (e[sort] is not None, e[sort] or "", e["key"]), reverse=body.get("direction", "desc") == "desc")
        page = int(body.get("page", 1))
        if page < 1:
            raise ValueError("Invalid page")
        return {"total": len(rows), "data": [{**{k: e[k] for k in ("key", "command_id", "account", "region", "document", "status", "requested_ms", "target_count")},
                "systems": len(e["systems"]), "events": len(e["events"]),
                "decoded": bool(e["base64_enrichment"])} for e in rows[(page-1)*100:page*100]],
                "loaded": bool(self.path), "limitations": self.limitations}

    def sheet(self, body):
        keys = {entry["key"] for entry in self.matching(body)}
        rows = [row for row in self.sheet_rows if row["key"] in keys]
        sorters = body.get("sorters") or [{"field": "requested_ms", "dir": "desc"}]
        fields = {"requested_ms", "command_id", "account", "region", "document", "instance_id", "plugin",
                  "status", "response_code", "parameters", "decoded", "stdout", "stderr", "combined_output", "events", "output_state"}
        if not isinstance(sorters, list) or len(sorters) > 5:
            raise ValueError("Use at most five sort columns")
        for sort in reversed(sorters):
            if not isinstance(sort, dict) or sort.get("field") not in fields or sort.get("dir") not in ("asc", "desc"):
                raise ValueError("Unknown spreadsheet sort")
            field = sort["field"]
            rows.sort(key=lambda row: (row[field] is not None, row[field] if row[field] is not None else ""),
                      reverse=sort["dir"] == "desc")
        page = int(body.get("page", 1))
        if page < 1:
            raise ValueError("Invalid page")
        return {"data": rows[(page-1)*100:page*100], "total": len(rows), "commands": len(keys),
                "loaded": bool(self.path), "limitations": self.limitations}

    def detail(self, body):
        entry = self.commands.get(body.get("key"))
        if entry is None:
            raise ValueError("Command not found")
        return {k: v for k, v in entry.items() if k != "search"}

    def event(self, body):
        event = self.events.get(body.get("key"))
        if event is None:
            raise ValueError("Linked event not found")
        return event

    def for_record(self, record):
        return [{"key": e["command_key"], "command_id": self.commands[e["command_key"]]["command_id"]}
                for e in self.events.values() if e["id"] == record]
