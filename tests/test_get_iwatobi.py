"""Setup CLI contracts with synthetic subprocess results; no network or Rust needed."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from kamotrace.cli import main
from kamotrace.get_iwatobi import REVISION, SOURCE


class IwatobiSetup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tools = Path(self.temp.name) / "tools with spaces"
        self.binary = b"synthetic executable"
        self.log = b"three\nidentical\noccurrences\n"
        digest = hashlib.sha256(self.log).hexdigest()
        self.bundle = {"schema": "iwatobi-forensic-1.0.0", "source_reference_profile": "uac-1.0.0",
            "alerts": [{"kind": "correlation", "members_total": 3, "members_truncated": False,
                "exact_members": 3, "evidence_status": "exact",
                "uac": {"acquisition": {"id": "synthetic-example-acquisition", "status": "supplied"}},
                "members": [{"evidence": {"location": {"status": "exact", "source_refs": [{
                    "collection_id": "synthetic-web-server", "path": "var/log/apache2/access.log",
                    "sha256": digest, "exact": True, "locator": {"kind": "text_line",
                        "coordinate": "decoded_decompressed_1_based", "line": line}}]}}} for line in (1, 2, 3)]}]}
        self.head = REVISION
        self.help = "--forensic-output <FILE> --evidence-manifest <FILE>"
        self.failure = None
        self.addCleanup(patch.stopall)
        patch("kamotrace.get_iwatobi.shutil.which", return_value="tool").start()
        patch("kamotrace.get_iwatobi.subprocess.run", side_effect=self.process).start()

    def process(self, command, cwd, **options):
        cwd = Path(cwd)
        if command[:2] == ["git", "clone"]:
            folder = Path(command[-1])
            (folder / "docs/examples/forensic").mkdir(parents=True)
            (folder / "docs/examples/forensic/access.log").write_bytes(self.log)
            (folder / "rules").mkdir()
            (folder / "config").mkdir()
            (folder / "LICENSE").write_text("RPL-1.5")
        elif command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, self.head, "")
        elif command[0] == "cargo":
            if self.failure:
                if isinstance(self.failure, Exception):
                    raise self.failure
                return subprocess.CompletedProcess(command, 1, "", self.failure)
            folder = Path(command[command.index("--target-dir") + 1]) / "release"
            folder.mkdir(parents=True)
            (folder / ("iwatobi.exe" if sys.platform == "win32" else "iwatobi")).write_bytes(self.binary)
        elif command[-1] == "--help":
            return subprocess.CompletedProcess(command, 0, self.help, "")
        elif "--forensic-output" in command:
            Path(command[command.index("--forensic-output") + 1]).write_text(json.dumps(self.bundle))
        return subprocess.CompletedProcess(command, 0, "", "")

    def invoke(self, *args, error=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            if error:
                with self.assertRaises(SystemExit) as caught:
                    main(["get-iwatobi", *args])
                self.assertEqual(caught.exception.code, 2)
                self.assertIn(error, err.getvalue())
                self.assertEqual(out.getvalue(), "")
                return
            main(["get-iwatobi", *args])
        return json.loads(out.getvalue())

    def test_install_retains_resources_and_reports_verified_pin(self):
        with patch.dict(os.environ, {"KAMOTRACE_TOOLS": str(self.tools)}):
            result = self.invoke()
        executable = Path(result["iwatobi"])
        self.assertEqual(executable.read_bytes(), self.binary)
        self.assertEqual(result["revision"], REVISION)
        self.assertEqual(result["source"], SOURCE)
        self.assertEqual(result["sha256"], hashlib.sha256(self.binary).hexdigest())
        self.assertEqual(result["smoke"], {"schema": "iwatobi-forensic-1.0.0",
                         "source_reference_profile": "uac-1.0.0", "exact_members": 3})
        folder = executable.parent
        self.assertTrue((folder / "rules").is_dir())
        self.assertTrue((folder / "config").is_dir())
        self.assertTrue((folder / "LICENSE").is_file())
        self.assertFalse((folder / "target").exists())
        self.assertEqual(json.loads((folder / "kamotrace-download.json").read_text())["revision"], REVISION)
        self.assertEqual(list(self.tools.iterdir()), [folder])
        self.invoke("--dest", str(self.tools), error="already exists")
        self.assertEqual(executable.read_bytes(), self.binary)

    def test_missing_prerequisite_and_build_failure_leave_no_install(self):
        with patch("kamotrace.get_iwatobi.shutil.which", side_effect=lambda tool: None if tool == "cargo" else "git"):
            self.invoke("--dest", str(self.tools), error="cargo is required")
        for failure, message in [("compiler diagnostic", "compiler diagnostic"),
                                 (subprocess.TimeoutExpired("cargo", 1800), "timed out")]:
            self.failure = failure
            self.invoke("--dest", str(self.tools), error=message)
            self.assertEqual(list(self.tools.iterdir()), [])

    def test_wrong_revision_and_upstream_capabilities_are_rejected(self):
        self.head = "0" * 40
        self.invoke("--dest", str(self.tools), error="does not match required")
        self.assertEqual(list(self.tools.iterdir()), [])
        self.head = REVISION
        self.help = "Iwatobi 1.0.0 without forensic flags"
        self.invoke("--dest", str(self.tools), error="lacks --forensic-output")
        self.assertEqual(list(self.tools.iterdir()), [])

    def test_incompatible_output_never_publishes(self):
        original = copy.deepcopy(self.bundle)
        for change, message in [("schema", "must produce"), ("line", "incompatible"),
                                ("sha256", "incompatible"), ("coordinate", "incompatible"),
                                ("members_truncated", "three exact"), ("exact", "incompatible")]:
            with self.subTest(change=change):
                self.bundle = copy.deepcopy(original)
                alert = self.bundle["alerts"][0]
                ref = alert["members"][1]["evidence"]["location"]["source_refs"][0]
                if change == "schema":
                    self.bundle["schema"] = "unsupported"
                elif change == "members_truncated":
                    alert[change] = True
                elif change in ("line", "coordinate"):
                    ref["locator"][change] = 1 if change == "line" else "bytes"
                else:
                    ref[change] = False if change == "exact" else "0" * 64
                self.invoke("--dest", str(self.tools), error=message)
                self.assertEqual(list(self.tools.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
