"""Low-frequency memory diagnostics, independent of evidence queries and payloads."""
import logging
from pathlib import Path, PurePosixPath
import re
import threading
import time

import duckdb
import psutil


logger = logging.getLogger(__name__)


def cgroup_memory():
    """Tightest finite unified-cgroup headroom, including ancestor limits, or None."""
    try:
        membership = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                          if line.startswith("0::"))
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            if " - cgroup2 " not in line:
                continue
            fields = line.split()
            unescape = lambda value: re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
            try:
                relative = PurePosixPath(membership).relative_to(unescape(fields[3]))
            except ValueError:
                continue
            if ".." in relative.parts:
                continue  # Membership outside the visible cgroup namespace is unknown.
            root = Path(unescape(fields[4]))
            current = root / relative
            bounds = []
            while True:
                try:
                    maximum = (current / "memory.max").read_text().strip()
                    if maximum != "max":
                        limit = int(maximum)
                        used = int((current / "memory.current").read_text())
                        stats = dict(line.split() for line in (current / "memory.stat").read_text().splitlines())
                        # Inactive file cache is reclaimable; usage alone overstates pressure.
                        available = min(limit, max(0, limit - used + int(stats.get("inactive_file", 0))))
                        if limit > 0:
                            bounds.append({"limit": limit, "used": used, "available": available})
                except (OSError, ValueError):
                    pass  # An unreadable limit is unknown, not unlimited or exhausted.
                if current == root:
                    return min(bounds, key=lambda b: b["available"] / b["limit"]) if bounds else None
                current = current.parent
    except (OSError, StopIteration):
        pass  # Non-Linux, cgroup v1, or an inaccessible unified hierarchy.
    return None


def memory_sample():
    system = psutil.virtual_memory()
    group = cgroup_memory()
    fraction = system.available / system.total
    scope = "system"
    if group is not None and group["available"] / group["limit"] < fraction:
        fraction, scope = group["available"] / group["limit"], "cgroup"
    return {"rss_bytes": psutil.Process().memory_info().rss,
            "system_total_bytes": system.total, "system_available_bytes": system.available,
            "cgroup_limit_bytes": group["limit"] if group else None,
            "cgroup_used_bytes": group["used"] if group else None,
            "cgroup_available_bytes": group["available"] if group else None,
            "headroom_percent": fraction * 100, "pressure_scope": scope}


class MemoryMonitor:
    """Sample every 30 seconds; warn/recover after two samples, with hysteresis."""

    def __init__(self, store):
        self.store = store
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="memory-monitor", daemon=True)
        self.low = self.healthy = 0
        self.pressure = False
        self.last_warning = float("-inf")

    def __enter__(self):
        self.thread.start()
        logger.info("Memory monitor started interval_seconds=30 warning_headroom_percent=10 recovery_headroom_percent=15")
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()

    def run(self):
        while not self.stop.wait(30):
            self.sample()

    def sample(self):
        try:
            sample = memory_sample()
        except (OSError, psutil.Error, ValueError) as error:
            self.low = self.healthy = 0
            logger.debug("memory sample unavailable error_type=%s", type(error).__name__)
            return
        fields = " ".join(f"{key}={value if value is not None else 'unknown'}" for key, value in sample.items())
        logger.debug("memory %s", fields)
        now = time.monotonic()
        if sample["headroom_percent"] <= 10:
            self.low += 1
            self.healthy = 0
            if self.low >= 2 and (not self.pressure or now - self.last_warning >= 300):
                self.pressure, self.last_warning = True, now
                logger.warning("Memory pressure: sustained headroom <=10%%; %s", fields)
        elif sample["headroom_percent"] >= 15:
            self.healthy += 1
            self.low = 0
            if self.pressure and self.healthy >= 2:
                self.pressure = False
                logger.info("Memory pressure recovered: sustained headroom >=15%%; %s", fields)
        else:
            self.low = self.healthy = 0
        if logger.isEnabledFor(logging.DEBUG):
            if not self.store.lock.acquire(blocking=False):
                logger.debug("memory duckdb=skipped_busy")
                return
            try:
                for tag, used in self.store.connection.execute(
                        "SELECT tag, sum(memory_usage_bytes) FROM duckdb_memory() GROUP BY tag").fetchall():
                    if used:
                        logger.debug("memory duckdb_tag=%s bytes=%d", tag, used)
            except duckdb.Error as error:
                logger.debug("memory duckdb=unavailable error_type=%s", type(error).__name__)
            finally:
                self.store.lock.release()
