"""Resumable, read-only AWS collection using the SDK's existing credential chain."""
import argparse
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from contextlib import contextmanager, ExitStack
from datetime import date, datetime, time, timedelta, timezone
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import statistics
import sqlite3
import sys
import threading
import time as clock
from urllib.parse import urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
import simplejson as json


LIMITATIONS = [
    "CloudTrail Event History: available management events only, last 90 days; not S3 trails, data events or CloudTrail Lake.",
    "SSM Run Command and terminated session history generally retain only 30 days; no recovery of expired records.",
    "Range selects event time / command RequestedDateTime / session StartDate, not overlapping sessions.",
    "Inline Run Command output may be truncated. Configured command S3/CloudWatch output is also collected.",
    "Session transcripts require --session-s3 and/or --session-log-group, existing logging and read permissions.",
    "Session SSH/port forwarding is not logged. Missing, expired, disabled or not-yet-delivered logs cannot be recovered.",
    "Collection is a resumable snapshot, not a live sync; completed requests are not refreshed on resume.",
    "Session records/transcripts are saved but are not displayed by the Run Command viewer.",
]
# LookupEvents permits two calls/second/account/Region. Each Region's daily windows share one pace,
# so two workers keep a slow (high-latency) connection near that limit without exceeding it.
LOOKUP_INTERVAL = 0.55
WINDOW_WORKERS = 2
# Show a CloudTrail ETA only after every unfinished Region has this much of its own AWS pace measured,
# and project a running day from its own density only once this fraction of it is covered.
ETA_MIN_PAGES = 10
ETA_MIN_SECONDS = 10
ETA_MIN_COVERAGE = 0.1


class Stopped(RuntimeError):
    """Another worker failed or the user interrupted; no further AWS calls are started."""


def timestamp(value, end=False):
    """Date ends include the entire UTC day; explicit timestamps are inclusive."""
    if len(value) == 10:
        result = datetime.combine(date.fromisoformat(value), time(), timezone.utc)
        return result + timedelta(days=1) - timedelta(microseconds=1) if end else result
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("ISO timestamps must include Z or a UTC offset; dates use UTC")
    return result.astimezone(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def encode(value):
    return json.dumps(value, default=iso, use_decimal=True, sort_keys=True, ensure_ascii=False)


@contextmanager
def json_output(path):
    """Atomically publish JSON, optionally gzip compressed with reproducible headers."""
    temporary = path.with_name(path.name + ".part")
    try:
        with ExitStack() as stack:
            raw = stack.enter_context(temporary.open("wb"))
            stream = stack.enter_context(gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0)) if path.suffix == ".gz" else raw
            output = stack.enter_context(io.TextIOWrapper(stream, encoding="utf-8", newline="\n"))
            yield output
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_json(path, value):
    with json_output(path) as output:
        output.write(encode(value) + "\n")


def minutes(seconds):
    if seconds < 60:
        return "<1m"
    hours, rest = divmod(round(seconds / 60), 60)
    return f"{hours}h{rest:02d}m" if hours else f"{rest}m"


def rough(seconds):
    """Round an estimate coarsely; finer figures would claim precision it does not have."""
    step = 60 if seconds < 600 else 300 if seconds < 3600 else 900
    return "<1m" if seconds < 60 else "~" + minutes(round(seconds / step) * step)


class Progress:
    """Region/service completion and CloudTrail daily window totals are known; AWS page totals are not."""
    def __init__(self, mode):
        self.mode = ("bar" if sys.stderr.isatty() else "log") if mode == "auto" else mode
        self.emoji = not os.environ.get("KAMOTRACE_NO_EMOJI")
        self.done, self.total, self.pages, self.cached = 0, 0, 0, 0
        self.last_bytes_tick = 0
        self.drawn = 0  # Bar rows on screen: the summary plus one per busy worker.
        self.lines = {}  # Worker thread -> its latest message.
        self.lock = threading.RLock()  # Region workers share counters and the terminal.
        self.started = clock.monotonic()
        # Region -> [windows, completed, fetched from AWS, first fetched window's start]; None without CloudTrail.
        self.regions, self.ssm, self.cloudtrail_done = None, False, None
        self.batches = {}  # Worker thread -> [Region, pages so far, fraction of its day covered or None].

    def plan(self, regions, windows, ssm):
        # left: unfinished windows; sizes: finished windows' pages (checkpoint replays included, as
        # sizes are real); fresh/since: pages fetched from AWS and when the first one arrived.
        self.regions = {region: {"left": windows, "sizes": [], "fresh": 0, "since": None}
                        for region in regions} if windows else None
        self.ssm = ssm

    def window_started(self, region):
        with self.lock:
            self.batches[threading.get_ident()] = [region, 0, None]

    def covered(self, fraction):
        """LookupEvents pages run newest first, so the oldest event so far shows how much of the day is done."""
        with self.lock:
            batch = self.batches[threading.get_ident()]
            batch[2] = max(batch[2] or 0, min(fraction, 1))

    def window_done(self):
        with self.lock:
            region, pages, _ = self.batches.pop(threading.get_ident())
            entry = self.regions[region]
            entry["left"] -= 1
            entry["sizes"].append(pages)
            if not any(entry["left"] for entry in self.regions.values()):
                self.cloudtrail_done = clock.monotonic()

    def remaining(self, now):
        """Seconds for the slowest Region at its own fetch pace, or None while there is too little to go on."""
        running = {}
        for region, pages, fraction in self.batches.values():
            running.setdefault(region, []).append((pages, fraction))
        longest = 0
        for region, entry in self.regions.items():
            if not entry["left"]:
                continue
            if entry["fresh"] < ETA_MIN_PAGES or now - entry["since"] < ETA_MIN_SECONDS:
                return None
            # The median, so one unusually busy day does not make every remaining day look busy.
            typical = statistics.median(entry["sizes"]) if len(entry["sizes"]) >= 2 else None
            batches = running.get(region, [])
            unstarted = entry["left"] - len(batches)
            if unstarted and typical is None:
                return None
            pages = unstarted * (typical or 0)
            for fetched, fraction in batches:
                if fraction is not None and fraction >= ETA_MIN_COVERAGE:
                    pages += fetched / fraction - fetched  # Extrapolate the day's own density.
                elif typical is not None and fetched <= typical:
                    pages += typical - fetched
                else:
                    return None  # Already larger than usual, too early in its day to project.
            # The first fresh page's own fetch time precedes "since", so it is not counted.
            longest = max(longest, pages * (now - entry["since"]) / (entry["fresh"] - 1))
        return longest

    def eta(self):
        parts = []
        if self.cloudtrail_done is not None:
            parts.append(f"CloudTrail done in {minutes(self.cloudtrail_done - self.started)}")
        elif self.regions:
            seconds = self.remaining(clock.monotonic())
            parts.append("CloudTrail ETA estimating" if seconds is None else f"CloudTrail ETA {rough(seconds)} (rough)")
        # SSM may run alongside CloudTrail, so finished jobs beyond finished CloudTrail Regions are SSM.
        # A Region's CloudTrail counts as finished slightly before its job does, which only delays this.
        ssm_done = self.done - sum(not entry["left"] for entry in self.regions.values()) if self.regions else self.done
        if self.ssm and ssm_done < (len(self.regions) if self.regions else self.total):
            parts.append("SSM ETA unknown")
        return "; ".join(parts)

    def tick(self, message, done=0, page=None):
        """Report message; done counts finished region/services, page is a page's cached flag."""
        with self.lock:
            self.done += done
            if page is not None:
                self.pages += 1
                self.cached += page
                batch = self.batches.get(threading.get_ident())
                if batch:
                    batch[1] += 1
                    entry = self.regions[batch[0]]
                    if not page:  # Checkpoint replays say nothing about AWS pace.
                        entry["fresh"] += 1
                        entry["since"] = entry["since"] or clock.monotonic()
            if self.mode == "off":
                return
            eta = self.eta()
            counts = f"{self.done}/{self.total} region/services | {self.pages} pages ({self.cached} cached)"
            counts += f" | {eta}" if eta else ""
            if self.mode == "log":
                print(f"{iso(datetime.now(timezone.utc))} {counts} | {message}", file=sys.stderr, flush=True)
            else:
                width = 20
                filled = width * self.done // self.total if self.total else 0
                if self.emoji:
                    ducks = max(1, filled // 2)
                    track = "🦆" * ducks + "-" * (width - 2 * ducks)
                else:
                    track = "#" * filled + "-" * (width - filled)
                # ETA precedes page counts so a narrow terminal truncates the less useful part.
                counts = f"{self.done}/{self.total} jobs " + (f"| {eta} | " if eta else "") + \
                    f"{self.pages} pages ({self.cached} cached)"
                size = shutil.get_terminal_size()
                columns = max(1, size.columns - 1)
                summary = f"[{track}] {counts}"
                summary_columns = max(1, columns - (ducks if self.emoji else 0))
                # One line per busy worker, sorted so a Region's lines stay together, oldest window first.
                self.lines[threading.get_ident()] = message
                details = sorted(self.lines.values())
                limit = max(1, size.lines - 2)  # Never scroll the block; scrolled lines cannot be redrawn.
                if len(details) > limit:
                    details = details[:limit - 1] + [f"... {len(details) - limit + 1} more workers"]
                rows = [summary[:summary_columns]] + [detail[:columns] for detail in details]
                # Return to the block's first line, redraw it, and clear lines left by finished workers.
                prefix = f"\r\033[{self.drawn - 1}A" if self.drawn > 1 else "\r"
                print(prefix + "\n".join("\r\033[2K" + row for row in rows) + "\033[J",
                      end="", file=sys.stderr, flush=True)
                self.drawn = len(rows)

    def idle(self):
        """The calling worker finished its task; drop its line at the next redraw."""
        with self.lock:
            self.lines.pop(threading.get_ident(), None)
            self.batches.pop(threading.get_ident(), None)  # A failed window.

    def transferred(self, size):
        with self.lock:
            now = clock.monotonic()
            if now - self.last_bytes_tick >= 1:
                self.tick(f"S3 object: {size} bytes downloaded")
                self.last_bytes_tick = now

    def close(self):
        with self.lock:
            if self.mode == "bar" and self.drawn:
                print(file=sys.stderr)
            self.mode = "off"


class Collector:
    def __init__(self, session, folder, start, end, progress, compress=False):
        self.session, self.folder, self.start, self.end = session, folder, start, end
        self.progress = progress
        self.compress = compress
        self.clients = {}
        # Region and window workers share this one connection; self.lock serializes every use of it.
        self.db = sqlite3.connect(folder / "checkpoint.sqlite", timeout=1, check_same_thread=False)
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.next_lookup = {}
        # Retain the SQLite lock across page commits; two collectors must not share a destination.
        self.db.execute("PRAGMA locking_mode=EXCLUSIVE")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS settings (value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pages (
                job TEXT, page INTEGER, response TEXT NOT NULL, PRIMARY KEY(job, page));
            CREATE TABLE IF NOT EXISTS events (
                region TEXT, id TEXT, raw TEXT NOT NULL, PRIMARY KEY(region, id));
            CREATE TABLE IF NOT EXISTS objects (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, etag TEXT);
        """)
        if "etag" not in {row[1] for row in self.db.execute("PRAGMA table_info(objects)")}:
            # Old hashes prove local integrity, but cannot bind bytes to an AWS object version.
            with self.db:
                self.db.execute("ALTER TABLE objects ADD COLUMN etag TEXT")

    def client(self, service, region):
        key = service, region
        with self.lock:  # Sessions are not thread-safe; the clients they create are.
            if key not in self.clients:
                self.clients[key] = self.session.client(service, region_name=region,
                    config=Config(retries={"mode": "adaptive", "max_attempts": 10},
                                  connect_timeout=15, read_timeout=60))
            return self.clients[key]

    def parallel(self, function, items, workers):
        """Run function(item) concurrently; the first failure or Ctrl+C stops every worker and is raised."""
        def run(item):
            try:
                return function(item)
            finally:
                self.progress.idle()

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = [pool.submit(run, item) for item in items]
            try:
                pending = futures
                while pending and not self.stopped.is_set():
                    # A timed wait keeps Ctrl+C responsive, including on Windows.
                    done, pending = wait(pending, timeout=0.5, return_when=FIRST_EXCEPTION)
                    if any(future.exception() for future in done):
                        self.stopped.set()
            except BaseException:
                self.stopped.set()
                raise
            finally:
                if self.stopped.is_set():
                    pool.shutdown(cancel_futures=True)  # Workers finish only their in-flight call.
        for future in futures:
            if not future.cancelled() and future.exception() and not isinstance(future.exception(), Stopped):
                raise future.exception()  # The real failure, not a worker it stopped.
        if self.stopped.is_set():
            raise Stopped("collection stopped by another worker")

    def pace(self, region):
        """Space LookupEvents call starts in a Region, shared by all of that Region's workers."""
        with self.lock:
            now = clock.monotonic()
            start = max(now, self.next_lookup.get(region, now))
            self.next_lookup[region] = start + LOOKUP_INTERVAL
        clock.sleep(start - now)

    def pages(self, service, region, operation, parameters, token="NextToken", result_token=None):
        """Commit each response and cursor together, including empty pages with a next token."""
        job = encode([service, region, operation, parameters])
        result_token = result_token or token
        index, cursor, restarted = 0, None, False
        seen = set()
        context = f"{region}: {operation}"
        if service == "cloudtrail":
            context += f" {iso(parameters['StartTime'])} to {iso(parameters['EndTime'])}"
        while True:
            with self.lock:
                cached = self.db.execute("SELECT response FROM pages WHERE job=? AND page=?", (job, index)).fetchone()
            if cached:
                response = json.loads(cached[0], use_decimal=True)
            else:
                request = dict(parameters)
                if cursor:
                    request[token] = cursor
                if service == "cloudtrail":
                    self.pace(region)
                if self.stopped.is_set():
                    raise Stopped("collection stopped by another worker")
                try:
                    response = getattr(self.client(service, region), operation)(**request)
                except ClientError as error:
                    code = error.response["Error"]["Code"]
                    message = error.response["Error"].get("Message", "").lower()
                    invalid_cursor = code in ("InvalidNextToken", "InvalidNextTokenException", "InvalidToken") or (
                        "token" in message and (service, code) in (
                            ("logs", "InvalidParameterException"), ("s3", "InvalidArgument")))
                    if cursor and not restarted and invalid_cursor:
                        # AWS cursors can expire while credentials are renewed. Rewalk and deduplicate.
                        with self.lock, self.db:
                            self.db.execute("DELETE FROM pages WHERE job=?", (job,))
                        index, cursor, restarted = 0, None, True
                        seen.clear()
                        self.progress.tick(f"{context} cursor expired; restarting pagination")
                        continue
                    raise
                response.pop("ResponseMetadata", None)
                with self.lock, self.db:
                    self.db.execute("INSERT INTO pages VALUES (?,?,?)", (job, index, encode(response)))
            self.progress.tick(f"{context} page {index + 1} {'cached' if cached else 'saved'}", page=bool(cached))
            yield response
            following = response.get(result_token)
            if not following:
                break
            if following in seen:
                raise RuntimeError(f"{operation} repeated a pagination token; refusing incomplete collection")
            seen.add(following)
            cursor, index = following, index + 1

    def selected(self, record, field):
        value = record[field]
        stamp = value if isinstance(value, datetime) else timestamp(value)
        return (self.start is None or self.start <= stamp) and stamp <= self.end

    def windows(self):
        lower = self.start if self.start is not None else self.end - timedelta(days=90)
        windows = []
        while True:
            upper = min(lower + timedelta(days=1), self.end)
            windows.append((lower, upper))
            if upper == self.end:
                return windows
            lower = upper

    def cloudtrail(self, region):
        # Oldest first: with default bounds the oldest window is the next to expire from Event History.
        self.parallel(lambda window: self.window(region, *window), self.windows(), WINDOW_WORKERS)

    def window(self, region, lower, upper):
        self.progress.window_started(region)
        self.progress.tick(f"{region}: CloudTrail batch {iso(lower)} to {iso(upper)}")
        for page in self.pages("cloudtrail", region, "lookup_events", {
                "StartTime": lower, "EndTime": upper, "MaxResults": 50}):
            with self.lock, self.db:
                for event in page.get("Events", []):
                    if self.selected(event, "EventTime"):
                        # Keep original JSON; shared inclusive batch boundaries deduplicate by ID.
                        self.db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?)",
                                        (region, event["EventId"], event["CloudTrailEvent"]))
            stamps = [event["EventTime"] for event in page.get("Events", [])]
            if stamps and upper > lower:
                oldest = min(value if isinstance(value, datetime) else timestamp(value) for value in stamps)
                self.progress.covered((upper - oldest) / (upper - lower))
        self.progress.window_done()

    def cloudwatch(self, region, group, prefix, logs):
        events = {}
        for page in self.pages("logs", region, "filter_log_events", {
                "logGroupName": group, "logStreamNamePrefix": prefix}, token="nextToken"):
            for event in page.get("events", []):
                events[event["eventId"]] = event
        identity = encode([region, group, prefix])
        name = hashlib.sha256(identity.encode()).hexdigest() + (".json.gz" if self.compress else ".json")
        atomic_json(self.folder / "logs" / name, {"region": region, "log_group": group,
                    "stream_prefix": prefix, "events": list(events.values())})
        logs[identity] = {"region": region, "log_group": group, "stream_prefix": prefix,
                          "file": "logs/" + name, "events": len(events)}

    def s3(self, region, bucket, prefix, logs, session_ids=None):
        for page in self.pages("s3", region, "list_objects_v2", {"Bucket": bucket, "Prefix": prefix},
                               token="ContinuationToken", result_token="NextContinuationToken"):
            for item in page.get("Contents", []):
                key = item["Key"]
                if session_ids is not None and not any(
                        part in session_ids or part.removesuffix(".log") in session_ids for part in key.split("/")):
                    continue
                identity = encode([bucket, key])
                name = hashlib.sha256(identity.encode()).hexdigest() + ".bin"
                target = self.folder / "logs" / name
                expected = item["Size"]
                with self.lock:
                    saved = self.db.execute("SELECT sha256, etag FROM objects WHERE name=?", (name,)).fetchone()
                if saved and saved[1] is not None and saved[1] != item["ETag"]:
                    raise RuntimeError(f"S3 object version conflict for s3://{bucket}/{key}: listings disagree; "
                                       "use a new destination for a fresh snapshot")
                digest = None
                if saved and saved[1] == item["ETag"] and target.exists() and target.stat().st_size == expected:
                    with target.open("rb") as source:
                        digest = hashlib.file_digest(source, "sha256").hexdigest()
                if not saved or digest != saved[0]:
                    if self.stopped.is_set():
                        raise Stopped("collection stopped by another worker")
                    response = self.client("s3", region).get_object(Bucket=bucket, Key=key, IfMatch=item["ETag"])
                    temporary = target.with_suffix(".part")
                    checksum = hashlib.sha256()
                    with response["Body"] as body, temporary.open("wb") as output:
                        transferred = 0
                        for block in iter(lambda: body.read(1 << 20), b""):
                            if self.stopped.is_set():  # A large transcript must not delay stopping.
                                raise Stopped("collection stopped by another worker")
                            output.write(block)
                            checksum.update(block)
                            transferred += len(block)
                            self.progress.transferred(transferred)
                    if temporary.stat().st_size != expected:
                        raise RuntimeError(f"Incomplete S3 object: s3://{bucket}/{key}")
                    temporary.replace(target)
                    digest = checksum.hexdigest()
                    with self.lock, self.db:
                        self.db.execute("INSERT OR REPLACE INTO objects (name, sha256, etag) VALUES (?,?,?)",
                                        (name, digest, item["ETag"]))
                logs[identity] = {"bucket": bucket, "key": key, "etag": item["ETag"],
                                  "size": expected, "sha256": digest, "file": "logs/" + name}

    def ssm(self, region, document, logs, session_s3, session_groups):
        # Widen server-side filters to whole seconds, then enforce inclusive microsecond bounds locally.
        filters = []
        if self.start is not None:
            filters.append({"key": "InvokedAfter", "value": iso(self.start.replace(microsecond=0) - timedelta(seconds=1))})
        filters.append({"key": "InvokedBefore", "value": iso(self.end.replace(microsecond=0) + timedelta(seconds=1))})
        commands = {}
        for page in self.pages("ssm", region, "list_commands", {"Filters": filters, "MaxResults": 50}):
            for command in page.get("Commands", []):
                if self.selected(command, "RequestedDateTime"):
                    commands[command["CommandId"]] = command
        for command_id, command in commands.items():
            document["commands"].append({"region": region, "record": command})
            invocations = {}
            for page in self.pages("ssm", region, "list_command_invocations", {
                    "CommandId": command_id, "Details": True, "MaxResults": 50}):
                for invocation in page.get("CommandInvocations", []):
                    invocations[invocation["InstanceId"]] = invocation
            for instance, invocation in invocations.items():
                document["invocations"].append({"region": region, "record": invocation})
                for plugin in invocation.get("CommandPlugins", []):
                    detail = next(self.pages("ssm", region, "get_command_invocation", {
                        "CommandId": command_id, "InstanceId": instance, "PluginName": plugin["Name"]}))
                    document["invocation_details"].append({"region": region, "record": detail})
            if command.get("OutputS3BucketName"):
                prefix = "/".join(p for p in (command.get("OutputS3KeyPrefix", "").rstrip("/"), command_id) if p) + "/"
                self.s3(region, command["OutputS3BucketName"], prefix, logs)
            config = command.get("CloudWatchOutputConfig", {})
            if config.get("CloudWatchOutputEnabled"):
                self.cloudwatch(region, config.get("CloudWatchLogGroupName") or
                                "/aws/ssm/" + command["DocumentName"], command_id + "/", logs)
        sessions = {}
        for state in ("Active", "History"):
            for page in self.pages("ssm", region, "describe_sessions", {
                    "State": state, "Filters": filters, "MaxResults": 100}):
                for record in page.get("Sessions", []):
                    if self.selected(record, "StartDate"):
                        sessions[record["SessionId"]] = record
        document["sessions"].extend({"region": region, "record": record} for record in sessions.values())
        for group in session_groups:
            for session_id in sessions:
                self.cloudwatch(region, group, session_id, logs)
        if sessions:
            for location in session_s3:
                parsed = urlsplit(location)
                self.s3(region, parsed.netloc, parsed.path.lstrip("/"), logs, set(sessions))

    def export_events(self):
        target = self.folder / ("cloudtrail.json.gz" if self.compress else "cloudtrail.json")
        with json_output(target) as output:
            output.write('{"Records":[')
            for index, (raw,) in enumerate(self.db.execute("SELECT raw FROM events ORDER BY region, id")):
                output.write((",\n" if index else "\n") + raw)
            output.write("\n]}\n")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace download", description=__doc__,
        epilog="Set KAMOTRACE_NO_EMOJI=1 for an ASCII-only bar. Rerun the same command to resume; use a new destination for fresh data.")
    parser.add_argument("--dest", required=True, type=Path, help="New private output directory, or same directory to resume")
    parser.add_argument("--profile", help="Existing AWS profile; otherwise use the normal SDK credential chain")
    parser.add_argument("--regions", nargs="+", required=True, help="Region names, or all enabled regions (space separated)")
    parser.add_argument("--start", help="Inclusive ISO timestamp with offset, or YYYY-MM-DD at UTC midnight; default: all available history")
    parser.add_argument("--end", help="Inclusive ISO timestamp with offset, or entire UTC date YYYY-MM-DD; default: collection start time")
    parser.add_argument("--services", nargs="+", choices=("cloudtrail", "ssm"), default=["cloudtrail", "ssm"])
    parser.add_argument("--compress", action="store_true", help="Gzip generated CloudTrail, SSM and CloudWatch JSON exports (not original S3 objects)")
    parser.add_argument("--progress", choices=("auto", "bar", "log", "off"), default="auto",
                        help="auto: bar on a terminal, timestamped tick log otherwise; off disables progress (stderr)")
    parser.add_argument("--session-s3", action="append", default=[], metavar="s3://BUCKET/PREFIX",
                        help="Existing session transcript location; repeatable, matched by exact session ID path/filename")
    parser.add_argument("--session-log-group", action="append", default=[], help="Existing session log group in selected regions; repeatable")
    args = parser.parse_args(argv)
    collector = None
    progress = Progress(args.progress)
    try:
        start = timestamp(args.start) if args.start else None
        end = timestamp(args.end, end=True) if args.end else datetime.now(timezone.utc)
        if start is not None and start > end:
            raise ValueError("Start must not be after end")
        if "all" in args.regions and args.regions != ["all"]:
            raise ValueError("Use all alone, or explicit region names")
        for location in args.session_s3:
            parsed = urlsplit(location)
            if parsed.scheme != "s3" or not parsed.netloc or parsed.query or parsed.fragment:
                raise ValueError("--session-s3 must be s3://BUCKET/PREFIX")
        if start is None:
            print("Warning: no --start supplied; downloading maximum available history. "
                  "CloudTrail Event History retains only 90 days; SSM history generally retains 30 days "
                  "(older active sessions may be available). Expired data cannot be recovered. "
                  "Collection may be large and take a long time.", file=sys.stderr, flush=True)
        session = boto3.Session(profile_name=args.profile)
        region = session.region_name or "us-east-1"
        progress.tick("Checking existing AWS login")
        identity = session.client("sts", region_name=region).get_caller_identity()
        folder = args.dest.resolve()
        if folder.exists() and not (folder / "checkpoint.sqlite").exists() and any(folder.iterdir()):
            raise ValueError("Destination is not an existing download or an empty directory")
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        collector = Collector(session, folder, start, end, progress, args.compress)
        settings = {"version": 1, "account_id": identity["Account"], "partition": identity["Arn"].split(":")[1],
                    "start": iso(start) if start is not None else None, "end": iso(end), "regions": sorted(set(args.regions)),
                    "compress": args.compress,
                    "services": sorted(set(args.services)), "session_s3": sorted(set(args.session_s3)),
                    "session_log_groups": sorted(set(args.session_log_group))}
        previous = collector.db.execute("SELECT value FROM settings").fetchone()
        previous_settings = json.loads(previous[0]) if previous else None
        if previous_settings is not None:
            previous_settings.setdefault("compress", False)
        if args.end is None:
            settings["end_default"] = True
            if previous_settings is not None and previous_settings.get("end_default"):
                settings["end"] = previous_settings["end"]
                collector.end = timestamp(settings["end"])
        if previous_settings is not None and previous_settings != settings:
            raise ValueError("Resume requires the same AWS account/partition, regions, range, services, compression and log locations; use a new destination")
        if not previous:
            with collector.db:
                collector.db.execute("INSERT INTO settings VALUES (?)", (encode(settings),))
        if args.regions == ["all"]:
            response = next(collector.pages("ec2", region, "describe_regions", {"AllRegions": False}))
            regions = sorted(item["RegionName"] for item in response["Regions"])
        else:
            regions = settings["regions"]
        progress.total = len(regions) * len(settings["services"])
        progress.plan(regions, len(collector.windows()) if "cloudtrail" in args.services else 0, "ssm" in args.services)
        manifest = {**settings, "resolved_regions": regions, "complete": False, "limitations": LIMITATIONS}
        atomic_json(folder / "manifest.json", manifest)
        (folder / "logs").mkdir(exist_ok=True)
        document = {"account_id": identity["Account"], "commands": [], "invocations": [],
                    "invocation_details": [], "sessions": [], "coverage": manifest}
        logs = {}
        # API quotas are per service and Region, so every Region's CloudTrail and SSM run concurrently.
        # SSM collects into its Region's own part; CloudTrail only into the checkpoint's events table.
        parts = {name: ({key: [] for key in ("commands", "invocations", "invocation_details", "sessions")}, {})
                 for name in regions}

        def collect(job):
            selected_region, service = job
            if service == "cloudtrail":
                collector.cloudtrail(selected_region)
            else:
                collector.ssm(selected_region, *parts[selected_region], args.session_s3, args.session_log_group)
            progress.tick(f"{selected_region}: {'CloudTrail' if service == 'cloudtrail' else 'SSM'} complete", done=1)
        progress.idle()  # Setup messages give way to the workers' lines.
        jobs = [(name, service) for name in regions for service in settings["services"]]
        collector.parallel(collect, jobs, len(jobs))
        for selected_region in regions:  # Merge in region order so exports do not depend on timing.
            region_document, region_logs = parts[selected_region]
            for key, records in region_document.items():
                document[key].extend(records)
            logs.update(region_logs)
        if "cloudtrail" in args.services:
            collector.export_events()
        manifest.update(complete=True, completed_at=iso(datetime.now(timezone.utc)), logs=list(logs.values()))
        if "ssm" in args.services:
            atomic_json(folder / ("ssm.json.gz" if args.compress else "ssm.json"), document)
        atomic_json(folder / "manifest.json", manifest)
        progress.close()
        print(f"Collection complete: {folder}")
        for limitation in LIMITATIONS:
            print(f"Note: {limitation}", file=sys.stderr)
        return 0
    except (BotoCoreError, ClientError, OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        progress.close()
        print(f"Download stopped: {error}\nRenew your AWS login if needed, then rerun the same command to resume.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        progress.close()
        print("Download interrupted; rerun the same command to resume.", file=sys.stderr)
        return 130
    finally:
        progress.close()
        if collector:
            collector.db.close()
