"""Explicit fresh-case orchestration, using synthetic acquisitions and no network."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kamotrace.cli import main
from kamotrace.datasets import read_case
from kamotrace.event_index import prepare
from kamotrace.importer import sha256, write_lock
from kamotrace.server import Store


class AutoContract(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.case = self.root / "case.json"
        self.source = self.root / "events.json"
        self.source.write_text(json.dumps({"Records": [{"eventID": "synthetic-A",
            "eventTime": "2026-10-01T00:00:00Z", "eventName": "GetCallerIdentity"}]}))

    def run_auto(self, *args, status=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = main(["auto", *map(str, args)])
            except SystemExit as error:
                result = error.code
        self.assertEqual(result, status, stderr.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def arguments(self, key="A"):
        return ["--case", self.case, "--unit", key, "--kind", "cloudtrail",
                "--source", self.source, "--no-serve"]

    def open_store(self):
        store = Store(case=self.case)
        self.addCleanup(store.selection_directory.cleanup)
        self.addCleanup(store.connection.close)
        self.addCleanup(store.reviews.close)
        return store

    def test_completed_retry_and_new_acquisition_preserve_previous_artifacts(self):
        before = sha256(self.source)
        output, _ = self.run_auto(*self.arguments())
        self.assertIn("[raw]", output)
        self.assertIn("[prepare]", output)
        first = read_case(self.case)
        self.run_auto(*self.arguments())
        self.assertEqual(read_case(self.case), first)
        self.run_auto(*self.arguments("B"))
        second = read_case(self.case)
        self.assertEqual(second["units"][0], first["units"][0])
        for kind in ("raw", "prepared"):
            artifact = first["units"][0][kind]
            self.assertEqual(sha256(Path(artifact["path"])), artifact["sha256"])
        store = self.open_store()
        self.assertEqual({r["id"] for r in store.query({})["data"]}, {1, 65537})
        self.assertEqual(sha256(self.source), before)

    def test_failed_preparation_keeps_raw_and_retries_without_readmission(self):
        with patch("kamotrace.auto.prepare", side_effect=OSError("synthetic full disk")):
            self.run_auto(*self.arguments(), status=1)
        pending = read_case(self.case)
        self.assertIsNone(pending["units"][0]["prepared"])
        with self.assertRaisesRegex(ValueError, "Preparation required"):
            Store(case=self.case)
        self.run_auto(*self.arguments())
        ready = read_case(self.case)
        self.assertEqual(ready["next_record"], pending["next_record"])
        self.assertEqual(ready["units"][0]["raw"], pending["units"][0]["raw"])

    def test_writer_contention_and_changed_inputs_fail_without_replacement(self):
        self.run_auto(*self.arguments())
        before = self.case.read_bytes()
        with write_lock(self.case):
            self.run_auto(*self.arguments(), status=1)
        self.source.write_text('{"Records":[{"eventID":"changed"}]}')
        self.run_auto(*self.arguments(), status=1)
        self.assertEqual(self.case.read_bytes(), before)

    def test_legacy_startup_fails_before_touching_evidence(self):
        original = self.source.read_bytes()
        _, error = self.run_auto(self.root, "--source", self.source, status=2)
        self.assertIn("re-ingest original inputs into a new case", error)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(self.case.exists())

    def test_serve_checks_entire_selection_instead_of_omitting_pending_units(self):
        self.run_auto(*self.arguments())
        from kamotrace.datasets import admit
        admit(self.case, "pending", "cloudtrail", [self.source])
        arguments = self.arguments()[:-1]
        self.run_auto(*arguments, status=2)
        prepare(self.case, ["pending"])
        store = self.open_store()
        self.assertEqual(store.meta["total"], 2)


if __name__ == "__main__":
    unittest.main()
