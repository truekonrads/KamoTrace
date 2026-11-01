"""Memory diagnostics: pressure signals, warning cadence and nonblocking sampling."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch

import duckdb

from kamotrace.memory import MemoryMonitor, cgroup_memory, memory_sample


class MemoryLogging(unittest.TestCase):
    def test_pressure_requires_sustained_low_headroom_and_recovers_with_hysteresis(self):
        store = SimpleNamespace(lock=threading.Lock())
        monitor = MemoryMonitor(store)
        # RSS alone cannot warn; exact 10/15% boundaries, reminder cadence and
        # intervening ambiguous/unknown samples distinguish the competing policies.
        readings = [80, 10, 9, 8, 7, 12, 15, 14, 15, 16, 9, None, 9, 9]
        times = iter([0, 30, 60, 90, 360, 390, 420, 450, 480, 510, 540, 600, 630])
        def sample():
            percent = readings.pop(0)
            if percent is None:
                raise OSError("Synthetic unavailable metric")
            return {"rss_bytes": 20_000_000_000, "headroom_percent": percent, "pressure_scope": "system"}
        with patch("kamotrace.memory.memory_sample", side_effect=sample), \
                patch("kamotrace.memory.time.monotonic", side_effect=lambda: next(times)), \
                self.assertLogs("kamotrace.memory", level="INFO") as captured:
            for _ in range(len(readings)):
                monitor.sample()
        messages = [r.getMessage() for r in captured.records]
        self.assertEqual(len(messages), 4)
        self.assertIn("headroom_percent=9", messages[0])
        self.assertIn("headroom_percent=7", messages[1])
        self.assertIn("recovered", messages[2])
        self.assertIn("headroom_percent=16", messages[2])
        self.assertIn("headroom_percent=9", messages[3])
        self.assertEqual([r.levelname for r in captured.records], ["WARNING", "WARNING", "INFO", "WARNING"])

    def test_container_ancestors_and_reclaimable_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "unified hierarchy"
            child = root / "child"
            child.mkdir(parents=True)
            for location, limit, used, cached in [(root, 1000, 980, 300), (child, 2000, 1000, 0)]:
                (location / "memory.max").write_text(str(limit))
                (location / "memory.current").write_text(str(used))
                (location / "memory.stat").write_text(f"inactive_file {cached}\n")
            original = Path.read_text
            def read(path, *args, **kwargs):
                if path == Path("/proc/self/cgroup"):
                    return "0::/slice/child\n"
                if path == Path("/proc/self/mountinfo"):
                    mount = str(root).replace(" ", r"\040")
                    return f"1 0 0:1 /slice {mount} rw - cgroup2 cgroup rw\n"
                return original(path, *args, **kwargs)
            with patch.object(Path, "read_text", read):
                self.assertEqual(cgroup_memory(), {"limit": 1000, "used": 980, "available": 320})
                (root / "memory.stat").write_text("inactive_file 0\n")
                with patch("kamotrace.memory.psutil.virtual_memory", return_value=SimpleNamespace(total=10_000, available=8000)):
                    result = memory_sample()
                self.assertEqual(result["pressure_scope"], "cgroup")
                self.assertEqual(result["headroom_percent"], 2)
                self.assertGreater(result["rss_bytes"], 0)
                (root / "memory.max").write_text("max")
                (child / "memory.max").write_text("max")
                self.assertIsNone(cgroup_memory())
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(cgroup_memory())
            self.assertEqual(memory_sample()["pressure_scope"], "system")

    def test_debug_sampler_skips_busy_connection_and_stops_cleanly(self):
        connection = duckdb.connect()
        store = SimpleNamespace(lock=threading.Lock(), connection=connection)
        try:
            connection.execute("CREATE TEMP TABLE example AS SELECT * FROM range(100)")
            with MemoryMonitor(store) as monitor, self.assertLogs("kamotrace.memory", level="DEBUG") as captured:
                with store.lock:
                    monitor.sample()  # Would deadlock if diagnostics waited for the query lock.
                monitor.sample()
            output = "\n".join(captured.output)
            self.assertIn("rss_bytes=", output)
            self.assertIn("system_available_bytes=", output)
            self.assertIn("duckdb=skipped_busy", output)
            self.assertIn("duckdb_tag=", output)
            self.assertFalse(monitor.thread.is_alive())
        finally:
            connection.close()
