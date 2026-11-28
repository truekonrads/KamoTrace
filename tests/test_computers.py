"""Read-only computer discovery and the real HTTP investigation API.

Prepared synthetic generic databases model the existing interchange format;
no producer, intake or registry writer is shipped by this release.
"""
from contextlib import ExitStack
from decimal import Decimal
from functools import partial
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import test_contract as contracts
import anyio
import duckdb
from mcp import Client
import simplejson as precise_json
from kamotrace.importer import sha256
from kamotrace.mcp_server import http_transport
from kamotrace.other_events import initialize, FORMAT
from kamotrace.server import Handler
from case_fixtures import open_fixture as Store
from kamotrace.suzaku import evidence_identity


def dataset(root, name, changes):
    folder = root / name
    folder.mkdir()
    stamp = "2021-03-08T10:00:00Z"
    manifest = {"run_id": "run-" + name, "collection_id": "collection-" + name,
        "analysis": {"status": "not_run"}, "coverage": {"events": len(changes), "sources_partial": 1},
        "settings": {"acquisition_id": "case-" + name, "acquisition_time": "2021-03-09T12:00:00Z",
                     "acquisition_basis": "supplied", "host": "caller collection label"}}
    database = folder / "events.duckdb"
    with duckdb.connect(str(database)) as connection:
        initialize(connection)
        from kamotrace.other_events import EVENTS_VIEW
        connection.execute("CREATE OR REPLACE VIEW events AS " + EVENTS_VIEW.replace("$.date", "$.@timestamp"))
        for i, change in enumerate(changes, 1):
            row = {"@timestamp": stamp, "event": {"id": f"{name}-{i}"},
                "uac": {"acquisition": {"id": "case-" + name}, "collection": {"id": "collection-" + name},
                    "source_refs": [{"path": "synthetic.log", "locator": {"line": i}}],
                    "time": {"basis": "source_claim", "selected": "claim",
                             "candidates": [{"id": "claim", "value": stamp}]}}}
            row.update(change)
            raw = json.dumps(row)
            content = hashlib.sha256(raw.encode()).hexdigest()
            identity = hashlib.sha256(f"{name}:{i}".encode()).hexdigest()
            connection.execute("INSERT INTO raw_events VALUES (?,?,?,?,?,?,?,?,?,?)",
                [i, raw, identity, "synthetic.jsonl", i, "Synthetic prepared acquisition", None, stamp, None, content])
        metadata = {"format": FORMAT, "records": len(changes), "source_sha256": "synthetic-" + name,
            "undated": sum(c.get("@timestamp", stamp) is None for c in changes),
            "origin": "Synthetic prepared acquisition", "imported_at": stamp,
            "adapter": "tracequarry-parse-only-v1", "tracequarry": {"manifest": manifest,
                "source_index": {"sources": [{"path": "synthetic.log", "status": "partial"}]}},
            "identity_policy": "manifest-sha256-and-physical-line; no cross-run deduplication"}
        connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps(metadata)])
    return database


def cloud(instance="i-example", account="123", region="ap-southeast-3"):
    return {"provider": "aws", "account": {"id": account}, "region": region, "instance": {"id": instance}}


def registry_fixture(database, value):
    """Test setup only; production exposes no registry mutation path."""
    with duckdb.connect(str(database.with_suffix(".uac.duckdb"))) as connection:
        connection.execute("CREATE OR REPLACE TABLE build_info(metadata JSON)")
        connection.execute("INSERT INTO build_info VALUES (?)", [precise_json.dumps(value, use_decimal=True)])


class ComputerContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def start(self, database, **options):
        self.store = Store(database, **options)
        self.addCleanup(self.store.connection.close)
        self.addCleanup(self.store.reviews.close)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=self.store))
        self.addCleanup(server.server_close)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_port}"
        self.transports = ExitStack()
        server.mcp_request = self.transports.enter_context(http_transport(self.url))
        self.addCleanup(self.transports.close)

    def call(self, route="/api/computers", body=None):
        request = Request(self.url + route, data=json.dumps(body or {}).encode(),
                          headers={"Content-Type": "application/json"})
        with urlopen(request) as response:
            return json.load(response)

    def test_multiple_imports_identity_gaps_conflicts_and_original_navigation(self):
        first = dataset(self.root, "one", [
            {"host": {"id": "machine-A", "name": "shared", "ip": ["10.0.1.5", "2001:db8::5"],
                      "os": {"name": "Linux"}, "uptime": 7200}},
            {"host": {"id": "machine-B", "name": "shared", "ip": ["10.0.1.9"], "uptime": 31}},
            {"host": {"id": "machine-A", "name": "renamed", "uptime": 9000}},
            {"host": {"name": "caller-name"}, "source": {"ip": "192.0.2.8"}},
            {"source": {"ip": "192.0.2.7"}, "tracequarry": {"host_display": "collection-label"}},
        ])
        second = dataset(self.root, "two", [{"host": {"id": "machine-A", "name": "different-import"}}])
        self.start(first, other_events=[second])
        result = self.call()
        self.assertEqual((len(result["imports"]), result["total"], result["scanned"]), (2, 4, 5))
        self.assertFalse(result["truncated"])
        a, b, label, unbound = result["cards"]
        self.assertEqual((a["identity"], b["identity"]), ("machine-A", "machine-B"))
        self.assertEqual([v["value"] for v in a["facts"]["hostname"]["values"]], ["shared", "renamed"])
        self.assertEqual([v["value"] for v in a["facts"]["uptime_seconds"]["values"]], [7200, 9000])
        self.assertEqual(a["acquisition_time"], "2021-03-09T12:00:00Z")
        self.assertEqual((label["identity_basis"], unbound["identity_basis"]), ("label", "unbound"))
        self.assertNotIn("host_ip", label["facts"])
        self.assertNotIn("host_ip", unbound["facts"])
        self.assertNotIn("uptime_seconds", unbound["facts"])
        self.assertEqual(a["acquisition_id"], "case-one")
        sample = a["facts"]["hostname"]["values"][0]["provenance"]
        with urlopen(self.url + f'/api/events/{sample["record"]}') as response:
            original = json.load(response)
        self.assertEqual(sample["record_sha256"], original["record_sha256"])
        self.assertEqual(json.loads(original["raw_json"])["host"]["uptime"], 7200)
        self.assertTrue(original["provenance"]["imports"])
        self.call("/api/reviews", {"action": "tag", "hashes": [sample["record_sha256"]], "slug": "card-reviewed", "color": "#112233"})
        finding = self.call("/api/reviews", {"action": "annotate", "hashes": [sample["record_sha256"]], "body": "Synthetic acquired uptime needs review"})
        with urlopen(self.url + f'/api/events/{sample["record"]}') as response:
            reviewed = json.load(response)
        self.assertEqual([t["slug"] for t in reviewed["tags"]], ["card-reviewed"])
        self.assertEqual(reviewed["annotations"], [finding["id"]])
        other = self.call(body={"unit_id": str(second)})
        self.assertEqual(other["cards"][0]["facts"]["hostname"]["values"][0]["value"], "different-import")
        self.assertEqual(self.call("/api/events")["last_row"], 6)
        self.assertEqual(self.call("/api/histogram")["total"], 6)
        for bad in ({"dataset_index": True}, {"dataset_index": -1}, {"page": 0}, {"page": "1"}):
            with self.assertRaises(HTTPError) as error:
                self.call(body=bad)
            self.assertEqual(error.exception.code, 400)

    def test_aws_exact_context_ambiguous_no_match_and_no_ip_guessing(self):
        changes = [
            {"host": {"id": "exact", "name": "application"}, "cloud": cloud()},
            {"host": {"id": "conflict"}, "cloud": cloud()},
            {"host": {"id": "conflict"}, "cloud": cloud("i-other", region="us-east-1")},
            {"host": {"id": "wrong-account"}, "cloud": cloud(account="999")},
            {"host": {"id": "wrong-region"}, "cloud": cloud(region="us-east-1")},
            {"host": {"name": "application", "ip": ["10.0.1.5"]}},
            {"host": {"name": "label-only"}, "cloud": cloud()},
            {"host": {"id": "incomplete"}, "cloud": {"provider": "aws", "instance": {"id": "i-example"}}},
        ]
        first = dataset(self.root, "aws", changes)
        inventory = self.root / "inventory"
        contracts.inventory_fixture(inventory)
        self.start(first, inventory_export=inventory)
        cards = self.call()["cards"] + self.call(body={"page": 2})["cards"]
        statuses = {c["identity"]: c["aws"]["status"] for c in cards}
        self.assertEqual(statuses, {"exact": "matched", "conflict": "ambiguous", "wrong-account": "no_match",
            "wrong-region": "no_match", "application": "unavailable", "label-only": "ambiguous", "incomplete": "unavailable"})
        exact = cards[0]["aws"]
        reference = self.call("/api/reference", {"kind": "machine", "value": exact["instance"],
            "account": exact["account"], "region": exact["region"], "include_history": False})
        self.assertEqual(len(reference["matches"]), 1)
        self.assertEqual(reference["matches"][0]["id"], "i-example")
        self.assertFalse(reference["history_included"])

    def test_empty_import_and_bounded_scan_disables_unqualified_links(self):
        first = dataset(self.root, "limited", [{"host": {"id": "same"}, "cloud": cloud()},
            {"host": {"id": "same"}, "cloud": cloud("i-other")}])
        empty = dataset(self.root, "empty", [])
        from case_fixtures import case_for
        with self.assertRaisesRegex(ValueError, "Empty acquisitions"):
            case_for(empty)
        self.start(first)
        with patch("kamotrace.computers.SCAN_LIMIT", 1):
            result = self.call()
        self.assertEqual((result["scanned"], result["truncated"]), (1, True))
        self.assertEqual(result["cards"][0]["aws"]["status"], "ambiguous")
        with self.assertRaises(HTTPError):
            self.call(body={"unit_id": str(empty)})

    def test_registered_discovery_preserves_inputs_reviews_and_mcp_navigation(self):
        primary = dataset(self.root, "primary", [{"host": {"id": "original"}}])
        additional = dataset(self.root, "registered", [{"@timestamp": None, "host": {"id": "registered"}}])
        with duckdb.connect(str(primary), read_only=True) as connection:
            identity = list(evidence_identity(connection))
        fraction = Decimal("1732212301.123456789012345678901")
        value = {"format": "kamotrace-uac-registry-v1", "evidence": identity,
            "imports": [{"database": str(additional), "sha256": sha256(additional),
                "ledger": {"status": "interrupted_not_completed", "whole_archive_status": "incomplete",
                           "omitted_links": [{"mtime": fraction}]}}],
            "attempts": [{"status": "in_progress"}]}
        registry_fixture(primary, value)
        protected = [primary, additional, primary.with_suffix(".uac.duckdb")]
        before = [(sha256(p), p.stat().st_mtime_ns) for p in protected]
        self.start(primary, other_events=[additional])  # Explicit+automatic must attach once.
        cards = self.call(body={"unit_id": str(additional)})
        self.assertEqual((len(cards["imports"]), cards["total"], cards["records"]), (2, 1, 1))
        record = cards["cards"][0]["sample_record"]
        self.assertEqual(record, 65537)
        for route in ("/api/meta", "/api/schema"):
            request = Request(self.url + route, data=b"{}", headers={"Content-Type": "application/json"})
            with urlopen(request) as response:
                loaded = precise_json.loads(response.read(), use_decimal=True)
            self.assertEqual({u["unit_id"] for u in loaded["case_coverage"]["units"]}, {"primary", str(additional)})
        self.assertEqual(self.call("/api/histogram")["total"], 1)
        self.assertEqual(self.call("/api/events", {"filters": [{"field": "time_local", "op": "missing"}]})["last_row"], 1)
        digest = cards["cards"][0]["facts"]["host_id"]["values"][0]["provenance"]["record_sha256"]
        self.call("/api/reviews", {"action": "tag", "hashes": [digest], "slug": "key-event", "color": "#112233"})
        note = self.call("/api/reviews", {"action": "annotate", "hashes": [digest], "body": "Preserve this exact observation"})

        async def session():
            async with Client(self.url + "/mcp") as client:
                schema = (await client.call_tool("describe_schema", {})).structured_content
                self.assertEqual((schema["events"], schema["undated"]), (2, 1))
                self.assertEqual(schema["source_coverage"][1]["sources"][0]["status"], "partial")
                found = (await client.call_tool("search_events", {"query": {"filters": [{"field": "time_local", "op": "missing"}]}})).structured_content
                self.assertEqual(found["total"], 1)
                original = (await client.call_tool("get_event", {"id": record})).structured_content
                self.assertTrue(original["raw_json_matches_hash"])
                self.assertEqual(json.loads(original["raw_json"])["host"]["id"], "registered")
                self.assertEqual([tag["slug"] for tag in original["tags"]], ["key-event"])
                self.assertEqual(original["annotations"], [note["id"]])
                self.assertEqual(original["provenance"]["imports"][0]["tracequarry"]["manifest"]["run_id"], "run-registered")
        anyio.run(session)
        self.assertEqual(before, [(sha256(p), p.stat().st_mtime_ns) for p in protected])
        with self.assertRaises(HTTPError) as error:
            self.call("/api/uac-alerts")
        self.assertEqual(error.exception.code, 404)

    def test_legacy_registry_is_never_adopted_or_modified(self):
        primary = dataset(self.root, "primary", [{}])
        additional = dataset(self.root, "additional", [{}])
        with duckdb.connect(str(primary), read_only=True) as connection:
            identity = list(evidence_identity(connection))
        valid = {"format": "kamotrace-uac-registry-v1", "evidence": identity,
                 "imports": [{"database": str(additional), "sha256": sha256(additional)}], "attempts": []}
        for changed in ({**valid, "evidence": ["wrong", 1]}, {**valid, "format": "wrong"},
                        {**valid, "imports": [{}]}, {**valid, "imports": "wrong"},
                        {**valid, "imports": [{"database": str(additional), "sha256": "0" * 64}]},
                        {**valid, "imports": [{"database": str(self.root / "missing.duckdb"), "sha256": "0" * 64}]}):
            with self.subTest(value=changed):
                registry_fixture(primary, changed)
                before = [sha256(p) for p in (primary, additional, primary.with_suffix(".uac.duckdb"))]
                from case_fixtures import case_for
                from kamotrace.server import Store as CaseStore
                store = CaseStore(case=case_for(primary))
                try:
                    self.assertEqual(store.meta["total"], 1)
                    self.assertEqual([u["unit_id"] for u in store.coverage["units"]], ["primary"])
                finally:
                    store.connection.close()
                    store.reviews.close()
                    store.selection_directory.cleanup()
                self.assertEqual(before, [sha256(p) for p in (primary, additional, primary.with_suffix(".uac.duckdb"))])

    def test_undated_only_primary_has_no_invented_histogram(self):
        primary = dataset(self.root, "undated", [{"@timestamp": None, "host": {"name": "unknown-time"}}])
        self.start(primary)
        self.assertEqual((self.store.meta["total"], self.store.meta["undated"], self.store.meta["start_ms"]), (1, 1, None))
        self.assertEqual(self.call("/api/histogram")["data"], [])
        self.assertEqual(self.call()["cards"][0]["identity"], "unknown-time")
        for query in ({"pipeline": "not a valid pipeline", "pipeline_version": 1},
                      {"pipeline": "", "pipeline_version": 9}, {"start": "invalid"},
                      {"filters": [{"field": "invented", "op": "eq", "value": "x"}]}):
            for route in ("/api/events", "/api/histogram"):
                with self.subTest(route=route, query=query):
                    with self.assertRaises(HTTPError) as error:
                        self.call(route, query)
                    self.assertEqual(error.exception.code, 400)
