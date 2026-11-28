"""Setup diagnostics and publication boundaries, without downloading optional tools."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from kamotrace.cli import main
from kamotrace.get_tracequarry import REVISION, install, run


class TraceQuarrySetupTests(unittest.TestCase):
    def test_existing_installation_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / f"tracequarry-{REVISION}"
            target.mkdir()
            marker = target / "original"
            marker.write_bytes(b"keep this installation")
            with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite"):
                install(Path(folder))
            self.assertEqual(marker.read_bytes(), b"keep this installation")

    def test_cli_missing_prerequisite_uses_tools_environment_and_explains_linker(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"KAMOTRACE_TOOLS": folder}):
            stderr = io.StringIO()
            with patch("kamotrace.get_tracequarry.shutil.which", return_value=None), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as error:
                    main(["get-tracequarry"])
            self.assertEqual(error.exception.code, 2)
            self.assertIn("Missing git", stderr.getvalue())
            self.assertIn("MSVC Build Tools + Windows SDK", stderr.getvalue())
            self.assertFalse((Path(folder) / f"tracequarry-{REVISION}").exists())

    def test_unavailable_revision_has_no_fallback_and_leaves_no_partial_install(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def unavailable(command, **kwargs):
                if str(command[0]) == "git" and command[1] == "fetch":
                    return subprocess.CompletedProcess(command, 128, stdout="not our ref", stderr="")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            # Model a successful clone without the required object, not another compatible version.
            def results(command, **kwargs):
                if command[:2] == ["git", "cat-file"]:
                    return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"")
                return unavailable(command, **kwargs)
            with patch("kamotrace.get_tracequarry.shutil.which", return_value="tool"), \
                    patch("kamotrace.get_tracequarry.subprocess.run", side_effect=results):
                with self.assertRaisesRegex(RuntimeError, "fork must publish this commit.*no fallback to main") as error:
                    install(root)
            self.assertIn(REVISION, str(error.exception))
            self.assertIn("not our ref", str(error.exception))
            self.assertFalse((root / f"tracequarry-{REVISION}").exists())
            self.assertEqual(list(root.glob(".tracequarry-*")), [])

    def test_failed_build_reports_stage_exit_and_compiler_diagnostic(self):
        with self.assertRaisesRegex(RuntimeError, "native build.*exit 7") as error:
            run([sys.executable, "-c", "import sys; print('linker not found'); sys.exit(7)"], stage="native build")
        self.assertIn("linker not found", str(error.exception))


if __name__ == "__main__":
    unittest.main()
