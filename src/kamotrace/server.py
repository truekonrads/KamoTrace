"""Local, read-only CloudTrail browser. Run with: kamotrace serve --database events.duckdb"""
import argparse
from collections import defaultdict
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, available_timezones

import duckdb


logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent
FIELDS = {
    "time_local": "Local time",
    "event_name": "Operation", "event_source": "AWS service", "identity": "Identity",
    "source_ip": "Source IP", "country": "Country", "key_id": "Access key ID",
    "target": "Target instance", "error_code": "Error code", "identity_type": "Identity type",
    "region": "Region", "user_agent": "User agent", "event_id": "Event ID",
    "document_name": "SSM document", "isp": "Network / ISP",
    "city": "City", "asn": "ASN", "ip_info": "IP attributes",
}
SORT_FIELDS = {*FIELDS, "time_local", "id"}
OPERATORS = {"eq", "neq", "in", "contains", "not_contains", "empty", "not_empty", "missing", "not_missing"}
PAGE_SIZES = (25, 50, 100, 250, 500)
LEVELS = ("informational", "low", "medium", "high", "critical")  # Suzaku/Sigma severity order
TIMEZONES = sorted(available_timezones() - {"localtime"})


class StaleSelection(ValueError):
    """A continuation page was requested for a selection whose membership may have changed."""


def query_timezone(body):
    zone = body.get("timezone", "UTC")
    if not isinstance(zone, str) or zone not in TIMEZONES:
        raise ValueError("Unknown timezone; choose an IANA timezone from metadata.timezones")
    return zone


def parse_time(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Time must be an ISO timestamp with a timezone") from None
    if parsed.tzinfo is None:
        raise ValueError("Time must include a timezone offset")
    return parsed


def build_query(body):
    """Only allowlisted SQL fragments; all user values remain bound parameters."""
    conditions, params = [], [query_timezone(body)]
    source = "(SELECT * REPLACE (strftime(event_time AT TIME ZONE ?, '%Y-%m-%d %H:%M:%S') AS time_local) FROM browse_events)"
    start, end = body.get("start"), body.get("end")
    if start:
        parse_time(start)
        conditions.append("event_time >= ?::TIMESTAMPTZ")
        params.append(start)
    if end:
        parse_time(end)
        conditions.append("event_time < ?::TIMESTAMPTZ")
        params.append(end)
    if start and end and parse_time(start) >= parse_time(end):
        raise ValueError("Start must be before end (the end is exclusive)")
    search = body.get("search", "")
    if not isinstance(search, str) or len(search) > 2000:
        raise ValueError("Search must be text, up to 2,000 characters")
    if search:
        # raw_event is stored JSON text, where " and \ (and control characters) appear escaped, so also
        # match the escaped form: `C:\Windows` is stored as `C:\\Windows`.
        escaped = json.dumps(search, ensure_ascii=False)[1:-1]
        conditions.append("(contains(lower(raw_event::VARCHAR), lower(?)) OR contains(lower(raw_event::VARCHAR), lower(?)))")
        params += [search, escaped]
    filters = body.get("filters", [])
    if not isinstance(filters, list) or len(filters) > 20:
        raise ValueError("Use at most 20 filters")
    for item in filters:
        field, op, value = item.get("field"), item.get("op"), item.get("value", "")
        if field not in FIELDS or op not in OPERATORS:
            raise ValueError("Unknown filter field or operator")
        if not isinstance(value, str) or len(value) > 2000:
            raise ValueError("Filter values must be text, up to 2,000 characters")
        if op in ("missing", "not_missing"):
            conditions.append(f"{field} IS {'NOT ' if op == 'not_missing' else ''}NULL")
        elif op in ("empty", "not_empty"):
            conditions.append(f"coalesce({field}, '') {'=' if op == 'empty' else '<>'} ''")
        elif op in ("eq", "neq"):
            conditions.append(f"{field} IS {'NOT ' if op == 'eq' else ''}DISTINCT FROM ?")
            params.append(value)
        elif op == "in":
            values = [v.strip() for v in value.split(",") if v.strip()]
            if not values or len(values) > 100:
                raise ValueError("One-of filters need 1 to 100 comma-separated values")
            conditions.append(f"{field} IN ({', '.join('?' for _ in values)})")
            params.extend(values)
        else:
            conditions.append(f"{'NOT ' if op == 'not_contains' else ''}contains(lower(coalesce({field}, '')), lower(?))")
            params.append(value)
    tags = body.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 20 or any(not isinstance(t, str) for t in tags):
        raise ValueError("Use at most 20 tags")
    for tag in tags:
        conditions.append("record_sha256 IN (SELECT hash FROM review_tags WHERE slug=?)")
        params.append(tag)
    if body.get("annotation_id") is not None:
        conditions.append("record_sha256 IN (SELECT hash FROM review_notes WHERE annotation_id=?)")
        params.append(int(body["annotation_id"]))
    if body.get("command_key") is not None:
        if not isinstance(body["command_key"], str):
            raise ValueError("Command key must be text")
        conditions.append("id IN (SELECT source_record FROM ssm_links WHERE command_key=?)")
        params.append(body["command_key"])
    # Imported Suzaku (Sigma) detections: every listed rule must match, like tags.
    rules = body.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 20 or any(not isinstance(r, str) for r in rules):
        raise ValueError("Use at most 20 detection rules")
    for rule in rules:
        conditions.append("id IN (SELECT source_record FROM detections WHERE rule_id=?)")
        params.append(rule)
    if body.get("min_level") is not None:
        if body["min_level"] not in LEVELS:
            raise ValueError("Minimum level must be one of: " + ", ".join(LEVELS))
        conditions.append("id IN (SELECT source_record FROM detections WHERE level_rank >= ?)")
        params.append(LEVELS.index(body["min_level"]))
    sorters = body.get("sorters") or [{"field": "time_local", "dir": "desc"}]
    if not isinstance(sorters, list) or len(sorters) > 5:
        raise ValueError("Use at most five sort columns")
    ordering = []
    for sorter in sorters:
        field, direction = sorter.get("field"), sorter.get("dir")
        if field not in SORT_FIELDS or direction not in ("asc", "desc"):
            raise ValueError("Unknown sort field or direction")
        ordering.append(f"{'event_time' if field == 'time_local' else field} {direction.upper()} NULLS LAST")
    ordering.append("id ASC")
    try:
        page, size = int(body.get("page", 1)), int(body.get("size", 100))
    except (TypeError, ValueError):
        raise ValueError("Page and size must be integers") from None
    if page < 1 or size not in PAGE_SIZES:
        raise ValueError("Invalid page or page size")
    where = "\nWHERE " + "\n  AND ".join(conditions) if conditions else ""
    sql = ("SELECT id, record_sha256, time_local, event_name, event_source, identity, source_ip, country,\n"
           "       identity_type, key_id, target, document_name, error_code, region, isp, city, asn, ip_info, user_agent, event_id\n"
           "FROM " + source + where + "\nORDER BY " + ", ".join(ordering) + "\nLIMIT ? OFFSET ?")
    return sql, params + [size, (page - 1) * size], "SELECT count(*) FROM " + source + where, params, size


class Store:
    def __init__(self, database, enrichment=None, annotations=None, ssm_export=None, detections=None):
        with ExitStack() as startup:
            logger.info("Opening evidence database (read-only): %s", database)
            self.connection = duckdb.connect(str(database), read_only=True)
            startup.callback(self.connection.close)
            self.connection.execute("SET TimeZone='UTC'; SET threads=2; SET memory_limit='2GB'")
            self.lock = threading.Lock()
            # Per-process prefix: a page-1 revision from before a restart never validates afterwards.
            self.log_revision = f"{secrets.token_hex(4)}-0"
            logger.info("Opening findings/tags sidecar: %s", annotations or database.with_suffix(".annotations.sqlite3"))
            self.reviews = sqlite3.connect(str(annotations or database.with_suffix(".annotations.sqlite3")), check_same_thread=False)
            startup.callback(self.reviews.close)
            self.reviews.row_factory = sqlite3.Row
            self.reviews.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS annotations(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL,
                    updated TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS annotation_events(annotation_id INTEGER REFERENCES annotations(id) ON DELETE CASCADE,
                    hash TEXT NOT NULL, PRIMARY KEY(annotation_id, hash));
                CREATE TABLE IF NOT EXISTS tags(slug TEXT PRIMARY KEY, color TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS event_tags(hash TEXT NOT NULL, slug TEXT REFERENCES tags(slug), PRIMARY KEY(hash, slug));
                CREATE TABLE IF NOT EXISTS sidecar_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ssm_log_reviews(entry_id TEXT PRIMARY KEY, text TEXT NOT NULL,
                    tags TEXT NOT NULL, finding TEXT NOT NULL, updated TEXT NOT NULL);
            """)
            # Bind the sidecar to its evidence on first use (older sidecars too), so another case's notes
            # can't be mixed in silently, as detections and enrichment sidecars already refuse.
            from .suzaku import evidence_identity
            logger.info("Validating findings/tags evidence identity")
            identity = json.dumps(list(evidence_identity(self.connection)))
            self.reviews.execute("INSERT OR IGNORE INTO sidecar_meta VALUES ('evidence', ?)", (identity,))
            self.reviews.commit()
            if self.reviews.execute("SELECT value FROM sidecar_meta WHERE key='evidence'").fetchone()[0] != identity:
                raise ValueError("This notes/tags sidecar belongs to a different evidence database; "
                                 "pass the right --annotations file or a new path")
            # Additive migration: older sidecars lack the query a note was written from.
            if "context" not in {r["name"] for r in self.reviews.execute("PRAGMA table_info(annotations)")}:
                self.reviews.execute("ALTER TABLE annotations ADD COLUMN context TEXT")
                self.reviews.commit()
            self.connection.execute("CREATE TEMP TABLE review_tags(hash VARCHAR, slug VARCHAR)")
            self.connection.execute("CREATE TEMP TABLE review_notes(hash VARCHAR, annotation_id BIGINT)")
            logger.info("Loading findings and event tags")
            self.refresh_reviews()
            from .enrich import load_enrichment
            # IP enrichment comes from a sidecar written by `kamotrace enrich` (GeoLite2 and/or neutral JSONL).
            default = database.with_suffix(".enrichment.duckdb")
            enrichment = enrichment or (default if default.exists() else None)
            logger.info("Loading IP enrichment: %s", enrichment or "none (no sidecar found)")
            self.enrichment_run = load_enrichment(self.connection, enrichment)
            logger.info("Preparing event browser view")
            self.connection.execute("""
                CREATE TEMP VIEW browse_events AS
                SELECT e.source_record AS id, e.record_sha256, e.event_id, e.event_time,
                    strftime(e.event_time AT TIME ZONE 'UTC', '%Y-%m-%d %H:%M:%S') AS time_local,
                    e.event_source, e.event_name, e.source_ip, e.identity_type,
                    coalesce(e.identity_arn, e.user_identity->>'$.userName',
                        e.user_identity->>'$.principalId', e.user_identity->>'$.invokedBy', '(unattributed)') AS identity,
                    e.user_identity->>'$.accessKeyId' AS key_id,
                    coalesce(e.request_parameters->>'$.target', e.request_parameters->>'$.instanceIds',
                        e.request_parameters->>'$.instanceId') AS target,
                    e.request_parameters->>'$.documentName' AS document_name,
                    e.error_code, e.aws_region AS region, e.user_agent, e.raw_event,
                    coalesce(g.country, '(unmapped / service / private)') AS country, g.isp, g.city, g.asn, g.ip_info
                FROM events e LEFT JOIN ip_enrichment g ON e.source_ip = g.ip
            """)
            from .ssm import Commands
            from .suzaku import load_detections
            logger.info("Loading and linking SSM commands: %s", ssm_export or "none (no export supplied)")
            self.commands = Commands(ssm_export, self.connection)
            # Suzaku detections come from a derived sidecar written by `kamotrace suzaku`; only rows the
            # CLI linked to exactly one evidence record are queryable. Missing sidecar = no detections.
            default = database.with_suffix(".detections.duckdb")
            detections = detections or (default if default.exists() else None)
            logger.info("Loading Suzaku detections: %s", detections or "none (no sidecar found)")
            self.suzaku_run = load_detections(self.connection, detections)
            # No endpoint accepts arbitrary SQL or paths. Also disable subsequent filesystem/network access.
            self.connection.execute("SET enable_external_access=false")
            logger.info("Calculating event counts, time range and filter metadata")
            self.meta = self.metadata()
            # The Store owns both connections after initialization succeeds.
            startup.pop_all()

    def ssm_log(self, body):
        with self.lock:
            entry_id = body.get("entry_id")
            if entry_id is not None:
                # Exact lookup (e.g. reading the latest saved review), independent of search, scope and time.
                if any(body.get(k) not in (None, "") for k in ("search", "search_scope", "start", "end", "page", "revision")):
                    raise ValueError("entry_id lookup takes no search, search_scope, time, page or revision")
                if not isinstance(entry_id, str) or entry_id not in self.commands.log_entries:
                    raise ValueError("Unknown current log entry")
                return {"data": self.log_review_data([self.commands.log_entries[entry_id]]), "total": 1,
                        "revision": self.log_revision, **self.commands.log_info()}
            analyst = None

            def analyst_text(entry):
                nonlocal analyst
                if analyst is None:  # Bulk-read once per request, only for searches that need it.
                    analyst = ({r[0]: "\0".join([r[1], *json.loads(r[2]), r[3]]).lower() for r in self.reviews.execute(
                                   "SELECT entry_id, text, tags, finding FROM ssm_log_reviews")},
                               defaultdict(list), defaultdict(list))
                    for hash_, slug in self.reviews.execute("SELECT hash, slug FROM event_tags"):
                        analyst[1][hash_].append(slug)
                    for hash_, note in self.reviews.execute("""SELECT e.hash, a.body FROM annotation_events e
                            JOIN annotations a ON a.id = e.annotation_id"""):
                        analyst[2][hash_].append(note.lower())
                saved, tags, notes = analyst
                hashes = [e["record_sha256"] for e in entry["events"] if e["record_sha256"]]
                return "\0".join([saved.get(entry["entry_id"], "")] + [v for h in hashes for v in tags[h] + notes[h]])

            result = self.commands.log(body, analyst_text)
            # Analyst content can move entries in or out of a review-dependent search between pages; an
            # offset continuation would then skip or repeat entries. Refuse it; the client refreshes explicitly.
            if result["review_dependent"] and body.get("page", 1) > 1 and body.get("revision") != self.log_revision:
                raise StaleSelection("Analyst content changed since this search ran; refresh the search (page 1) "
                                     "to continue. Pass the revision returned with page 1 for later pages.")
            # Saved reviews whose source content is no longer an entry (changed export or grouping) stay
            # readable rather than silently disappearing; they are never attached to another entry.
            unmatched = [{"entry_id": r["entry_id"], "text": r["text"], "tags": json.loads(r["tags"]),
                          "finding": r["finding"], "updated": r["updated"]}
                         for r in self.reviews.execute("SELECT * FROM ssm_log_reviews ORDER BY updated, entry_id")
                         if r["entry_id"] not in self.commands.log_entries]
            return {**result, "data": self.log_review_data(result["data"]), "revision": self.log_revision,
                    "unmatched_reviews": unmatched}

    def log_review_data(self, entries):
        """Attach each entry's saved review and its linked events' tags/findings (read-only here). Caller holds the lock."""
        ids = json.dumps([e["entry_id"] for e in entries])
        hashes = json.dumps(list({e["record_sha256"] for entry in entries for e in entry["events"] if e["record_sha256"]}))
        saved = {r["entry_id"]: {"text": r["text"], "tags": json.loads(r["tags"]), "finding": r["finding"], "updated": r["updated"]}
                 for r in self.reviews.execute("SELECT * FROM ssm_log_reviews WHERE entry_id IN (SELECT value FROM json_each(?))", (ids,))}
        tags, notes = defaultdict(list), defaultdict(list)
        for r in self.reviews.execute("""SELECT t.hash, t.slug, g.color FROM event_tags t JOIN tags g ON g.slug = t.slug
                WHERE t.hash IN (SELECT value FROM json_each(?)) ORDER BY t.slug""", (hashes,)):
            tags[r["hash"]].append({"slug": r["slug"], "color": r["color"]})
        for r in self.reviews.execute("""SELECT e.hash, a.id, a.body, a.updated FROM annotation_events e
                JOIN annotations a ON a.id = e.annotation_id WHERE e.hash IN (SELECT value FROM json_each(?)) ORDER BY a.id""", (hashes,)):
            notes[r["hash"]].append({"id": r["id"], "body": r["body"], "updated": r["updated"]})
        return [{**entry, "review": saved.get(entry["entry_id"], {"text": "", "tags": [], "finding": "", "updated": None}),
                 "events": [{**e, "tags": tags.get(e["record_sha256"], []), "findings": notes.get(e["record_sha256"], [])}
                            for e in entry["events"]]} for entry in entries]

    def bump_log_revision(self, hashes=None):
        """Advance the log selection revision after analyst content changed (entry reviews, or event
        tags/findings on evidence linked to log entries). Caller holds the lock."""
        if hashes is None or not self.commands.log_hashes.isdisjoint(hashes):
            prefix, count = self.log_revision.rsplit("-", 1)
            self.log_revision = f"{prefix}-{int(count) + 1}"

    def ssm_log_review(self, body):
        with self.lock, self.reviews:
            entry_id = body.get("entry_id")
            if not isinstance(entry_id, str) or entry_id not in self.commands.log_entries:
                raise ValueError("Unknown current log entry")
            text, tags, finding = body.get("text"), body.get("tags"), body.get("finding")
            if any(not isinstance(value, str) or len(value) > 30000 for value in (text, finding)):
                raise ValueError("Review text and finding must be text up to 30,000 characters")
            if (not isinstance(tags, list) or len(tags) > 100 or any(not isinstance(tag, str) or len(tag) > 256
                    or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", tag) for tag in tags)):
                raise ValueError("Use at most 100 lowercase hyphen-separated tag slugs, at most 256 characters each")
            current = self.reviews.execute("SELECT updated FROM ssm_log_reviews WHERE entry_id=?", (entry_id,)).fetchone()
            if "updated" not in body or body["updated"] != (current["updated"] if current else None):
                raise ValueError("This log review changed since it was loaded; reload it and reapply your change")
            review = {"text": text, "tags": sorted(set(tags)), "finding": finding,
                      "updated": datetime.now(timezone.utc).isoformat()}
            self.reviews.execute("""INSERT INTO ssm_log_reviews VALUES (?,?,?,?,?) ON CONFLICT(entry_id)
                DO UPDATE SET text=excluded.text,tags=excluded.tags,finding=excluded.finding,updated=excluded.updated""",
                (entry_id, text, json.dumps(review["tags"]), finding, review["updated"]))
            self.bump_log_revision()
            return review

    def refresh_reviews(self):
        for table, source in (("review_tags", "SELECT hash,slug FROM event_tags"),
                              ("review_notes", "SELECT hash,annotation_id FROM annotation_events")):
            self.connection.execute(f"DELETE FROM {table}")
            rows = [tuple(r) for r in self.reviews.execute(source)]
            if rows:
                self.connection.executemany(f"INSERT INTO {table} VALUES (?,?)", rows)

    def reviews_list(self):
        with self.lock:
            # Counts are evidence events (rows), across the whole database, independent of the current query.
            tag_counts = dict(self.connection.execute("""SELECT r.slug, count(*) FROM review_tags r
                JOIN events e ON e.record_sha256 = r.hash GROUP BY 1""").fetchall())
            note_counts = dict(self.connection.execute("""SELECT r.annotation_id, count(*) FROM review_notes r
                JOIN events e ON e.record_sha256 = r.hash GROUP BY 1""").fetchall())
            notes = []
            for row in self.reviews.execute("""SELECT a.id, a.body, a.updated, a.context FROM annotations a
                    WHERE EXISTS (SELECT 1 FROM annotation_events e WHERE e.annotation_id=a.id)
                    ORDER BY a.updated DESC, a.id DESC"""):
                note = dict(row)
                note["context"] = json.loads(note["context"]) if note["context"] else None
                note["events"] = note_counts.get(note["id"], 0)
                notes.append(note)
            return {"annotations": notes, "tags": [{**dict(r), "events": tag_counts.get(r["slug"], 0)}
                                                   for r in self.reviews.execute("SELECT * FROM tags ORDER BY slug")]}

    def review_write(self, body):
        action = body.get("action")
        with self.lock:
            with self.reviews:
                if action in ("annotate", "tag", "untag", "link", "unlink"):
                    hashes = body.get("hashes")
                    if not isinstance(hashes, list) or not 1 <= len(hashes) <= 5000 or any(not isinstance(h, str) for h in hashes):
                        raise ValueError("Select 1 to 5,000 events")
                    hashes = list(set(hashes))
                    found = self.connection.execute("SELECT DISTINCT record_sha256 FROM events WHERE record_sha256 IN (SELECT unnest(?))", [hashes]).fetchall()
                    if len(found) != len(hashes):
                        raise ValueError("Unknown event hash")
                stamp = datetime.now(timezone.utc).isoformat()
                changed = set(hashes) if action in ("annotate", "tag", "untag", "link", "unlink") else set()
                if action in ("edit", "delete"):
                    changed = {r[0] for r in self.reviews.execute("SELECT hash FROM annotation_events WHERE annotation_id=?",
                                                                  (int(body.get("id")),))}
                    # Optimistic concurrency: the browser and agents share this sidecar, so a writer must
                    # quote the version it read; a stale edit/delete fails instead of overwriting.
                    current = self.reviews.execute("SELECT updated FROM annotations WHERE id=?", (int(body.get("id")),)).fetchone()
                    if current is None:
                        raise ValueError("Unknown annotation")
                    if body.get("updated") != current["updated"]:
                        raise ValueError("This note changed since it was loaded (another tab or agent wrote it); "
                                         "reload it and reapply your change")
                if action in ("annotate", "edit"):
                    text = body.get("body")
                    if not isinstance(text, str) or not text.strip() or len(text) > 30000:
                        raise ValueError("Annotation must contain 1 to 30,000 characters")
                    if action == "annotate":
                        # Optional browser query state the note was written from; it is re-validated by
                        # build_query whenever it is reopened, so it is stored as inert JSON text only.
                        context = body.get("context")
                        if context is not None:
                            if not isinstance(context, dict):
                                raise ValueError("Note context must be a JSON object")
                            context = json.dumps(context, ensure_ascii=False)
                            if len(context) > 20000:
                                raise ValueError("Note context is too large")
                        cursor = self.reviews.execute("INSERT INTO annotations(body,updated,context) VALUES (?,?,?)", (text, stamp, context))
                        self.reviews.executemany("INSERT INTO annotation_events VALUES (?,?)", [(cursor.lastrowid, h) for h in hashes])
                    else:
                        self.reviews.execute("UPDATE annotations SET body=?,updated=? WHERE id=?", (text, stamp, int(body.get("id"))))
                elif action == "delete":
                    self.reviews.execute("DELETE FROM annotations WHERE id=?", (int(body.get("id")),))
                elif action in ("link", "unlink"):
                    note = int(body.get("id"))
                    if not self.reviews.execute("SELECT 1 FROM annotations WHERE id=?", (note,)).fetchone():
                        raise ValueError("Unknown annotation")
                    if action == "link":
                        self.reviews.executemany("INSERT OR IGNORE INTO annotation_events VALUES (?,?)", [(note, h) for h in hashes])
                    else:
                        self.reviews.executemany("DELETE FROM annotation_events WHERE annotation_id=? AND hash=?", [(note, h) for h in hashes])
                        if not self.reviews.execute("SELECT 1 FROM annotation_events WHERE annotation_id=?", (note,)).fetchone():
                            raise ValueError("A note needs at least one linked event; delete the note instead")
                    self.reviews.execute("UPDATE annotations SET updated=? WHERE id=?", (stamp, note))
                elif action == "color":
                    slug, color = body.get("slug"), body.get("color", "")
                    if not isinstance(color, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
                        raise ValueError("Choose a six-digit hex color")
                    if not self.reviews.execute("UPDATE tags SET color=? WHERE slug=?", (color, slug)).rowcount:
                        raise ValueError("Unknown tag")
                elif action in ("tag", "untag"):
                    slug = body.get("slug", "")
                    if not isinstance(slug, str) or len(slug) > 256 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
                        raise ValueError("Tags must be lowercase hyphen-separated slugs, at most 256 characters")
                    if action == "tag":
                        color = body.get("color", "")
                        if not isinstance(color, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
                            raise ValueError("Choose a six-digit hex color")
                        self.reviews.execute("INSERT INTO tags VALUES (?,?) ON CONFLICT(slug) DO UPDATE SET color=excluded.color", (slug, color))
                        self.reviews.executemany("INSERT OR IGNORE INTO event_tags VALUES (?,?)", [(h, slug) for h in hashes])
                    else:
                        self.reviews.executemany("DELETE FROM event_tags WHERE hash=? AND slug=?", [(h, slug) for h in hashes])
                else:
                    raise ValueError("Unknown review action")
            self.refresh_reviews()
            self.bump_log_revision(changed)
            revision = self.log_revision
        return {"ok": True, "log_revision": revision, **({"id": cursor.lastrowid} if action == "annotate" else {}),
                **({"updated": stamp} if action in ("annotate", "edit", "link", "unlink") else {})}

    def rows(self, sql, params=None):
        result = self.connection.execute(sql, params or [])
        names = [column[0] for column in result.description]
        return [dict(zip(names, row)) for row in result.fetchall()]

    def metadata(self, body=None):
        zone = query_timezone(body or {})
        bounds = self.rows("""SELECT count(*) AS total, min(epoch_ms(event_time)) AS start_ms,
            max(epoch_ms(event_time)) + 1000 AS end_ms FROM browse_events""")[0]
        histogram = self.rows("""SELECT strftime(event_time AT TIME ZONE ?, '%Y-%m-%d') AS day,
            count(*) AS total, count(*) FILTER (WHERE event_source='ssm.amazonaws.com'
            AND event_name IN ('SendCommand','StartSession')) AS ssm
            FROM browse_events GROUP BY 1 ORDER BY 1""", [zone])
        for row in histogram:
            day = datetime.fromisoformat(row["day"]).replace(tzinfo=ZoneInfo(zone))
            row["start_ms"] = int(day.timestamp() * 1000)
            row["end_ms"] = int((day + timedelta(days=1)).timestamp() * 1000)
        facets = {field: [r["value"] for r in self.rows(
            f"SELECT DISTINCT {field} AS value FROM browse_events WHERE {field} IS NOT NULL ORDER BY 1")]
            for field in ("event_name", "event_source", "country", "identity_type", "error_code", "document_name")}
        return {**bounds, "histogram": histogram, "facets": facets, "fields": FIELDS,
                "operators": sorted(OPERATORS), "sort_fields": sorted(SORT_FIELDS), "page_sizes": PAGE_SIZES,
                "levels": LEVELS, "detections_loaded": self.suzaku_run is not None,
                "enrichment": self.enrichment_run,
                "timezone": zone, "timezones": TIMEZONES, "database": "cloudtrail.duckdb", "read_only": True}

    def timezone_metadata(self, body):
        with self.lock:
            return self.metadata(body)

    def query(self, body):
        sql, params, count_sql, count_params, size = build_query(body)
        started = time.monotonic()
        with self.lock:
            total = self.connection.execute(count_sql, count_params).fetchone()[0]
            rows = self.rows(sql, params)
            found = self.row_detections([row["id"] for row in rows])
            for row in rows:
                row["tags"] = [dict(r) for r in self.reviews.execute("SELECT t.* FROM tags t JOIN event_tags e USING(slug) WHERE e.hash=? ORDER BY slug", (row["record_sha256"],))]
                row["annotations"] = [r[0] for r in self.reviews.execute("SELECT annotation_id FROM annotation_events WHERE hash=?", (row["record_sha256"],))]
                row["detections"] = found.get(row["id"], [])
        return {"data": rows, "last_page": max(1, math.ceil(total / size)), "last_row": total,
                "sql": sql, "params": params, "elapsed_ms": round((time.monotonic() - started) * 1000)}

    def histogram(self, body):
        zone = query_timezone(body)
        width = body.get("bucket_minutes", 1440)
        if not str(width).isdigit() or not 1 <= int(width) <= 525600:
            raise ValueError("Bucket width must be 1 to 525,600 whole minutes")
        minutes = int(width)
        start = body.get("start") or datetime.fromtimestamp(self.meta["start_ms"] / 1000, timezone.utc).isoformat()
        end = body.get("end") or datetime.fromtimestamp(self.meta["end_ms"] / 1000, timezone.utc).isoformat()
        _, _, count_sql, params, _ = build_query({**body, "start": start, "end": end})
        if (parse_time(end) - parse_time(start)).total_seconds() / (minutes * 60) > 2000:
            raise ValueError("More than 2,000 buckets: choose a larger bucket or a shorter time range")
        # Enumerate wall-clock boundaries, retaining both folds and skipping nonexistent times.
        # Sorting their real instants gives 23/25-hour days and distinct repeated-hour buckets.
        tz = ZoneInfo(zone)
        first, until = parse_time(start), parse_time(end)
        step = timedelta(minutes=minutes)
        anchor = datetime(2000, 1, 3)  # Same Monday origin as DuckDB time_bucket for minute intervals.
        low = first.astimezone(tz).replace(tzinfo=None) - timedelta(days=2)
        high = until.astimezone(tz).replace(tzinfo=None) + timedelta(days=2) + step
        wall = anchor + ((low - anchor) // step) * step
        edges = set()
        while wall <= high:
            for fold in (0, 1):
                instant = wall.replace(tzinfo=tz, fold=fold)
                if instant.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None) == wall:
                    edges.add(int(instant.timestamp() * 1000))
            wall += step
        edges = sorted(edges)
        ranges = [(a, b) for a, b in zip(edges, edges[1:])
                  if a < until.timestamp() * 1000 and b > first.timestamp() * 1000]
        if len(ranges) > 2000:
            raise ValueError("More than 2,000 buckets: choose a larger bucket or a shorter time range")
        sql = """WITH matching AS (
        """ + count_sql.replace("SELECT count(*)", "SELECT epoch_ms(event_time) AS event_ms", 1) + """
        ), buckets AS (
            SELECT unnest(?::BIGINT[]) AS start_ms, unnest(?::BIGINT[]) AS end_ms
        )
        SELECT strftime(make_timestamptz(b.start_ms * 1000) AT TIME ZONE ?, '%Y-%m-%d %H:%M:%S') AS bucket_start_local,
               b.start_ms, b.end_ms, count(m.event_ms) AS events
        FROM buckets b LEFT JOIN matching m ON m.event_ms >= b.start_ms AND m.event_ms < b.end_ms
        GROUP BY b.start_ms, b.end_ms ORDER BY b.start_ms"""
        bound = params + [[a for a, _ in ranges], [b for _, b in ranges], zone]
        with self.lock:
            rows = self.rows(sql, bound)
        return {"data": rows, "total": sum(r["events"] for r in rows),
                "bucket_minutes": minutes, "sql": sql, "params": bound}

    def column_values(self, body):
        field = body.get("field")
        if field not in {*FIELDS, "time_local"}:
            raise ValueError("Unknown summary column")
        _, _, count_sql, params, _ = build_query(body)
        if "value" in body:
            value = body["value"]
            if value is not None and not isinstance(value, str):
                raise ValueError("Cell values must be text or null")
            sql = count_sql.replace("SELECT count(*)", f"SELECT count(*) AS total, "
                f"count(*) FILTER (WHERE {field} IS NOT DISTINCT FROM ?) AS events", 1)
            with self.lock:
                return self.rows(sql, [value, *params])[0]
        sql = """WITH counts AS (
        """ + count_sql.replace("SELECT count(*)", f"SELECT {field} AS value, count(*) AS events", 1) + """
            GROUP BY 1
        ), ranked AS (
            SELECT *, row_number() OVER (ORDER BY events DESC, value ASC NULLS LAST) AS top_rank,
                row_number() OVER (ORDER BY events ASC, value ASC NULLS LAST) AS bottom_rank,
                sum(events) OVER () AS total, count(*) OVER () AS distinct_values
            FROM counts
        ) SELECT * FROM ranked WHERE top_rank <= 5 OR bottom_rank <= 5"""
        with self.lock:
            rows = self.rows(sql, params)
        return {"top": [{"value": r["value"], "events": r["events"]}
                        for r in sorted(rows, key=lambda r: r["top_rank"]) if r["top_rank"] <= 5],
                "bottom": [{"value": r["value"], "events": r["events"]}
                           for r in sorted(rows, key=lambda r: r["bottom_rank"]) if r["bottom_rank"] <= 5],
                "total": int(rows[0]["total"]) if rows else 0,
                "distinct_values": rows[0]["distinct_values"] if rows else 0}

    def detail(self, record):
        with self.lock:
            rows = self.rows("SELECT event_id, record_sha256, raw_event::VARCHAR AS raw_json FROM events WHERE source_record=?", [record])
            if rows:
                rows[0]["ssm_commands"] = self.commands.for_record(record)
                rows[0]["detections"] = self.row_detections([record]).get(record, [])
        return rows[0] if rows else None

    def row_detections(self, records):
        """Suzaku rule matches per evidence record, most severe first. Caller holds the lock."""
        found = {}
        for record, rule_id, title, level, tactics, techniques in self.connection.execute("""
                SELECT source_record, rule_id, rule_title, level, tactics, technique_ids FROM detections
                WHERE source_record IN (SELECT unnest(?)) ORDER BY level_rank DESC, rule_title""", [records]).fetchall():
            found.setdefault(record, []).append({"rule_id": rule_id, "title": title, "level": level,
                                                  "tactics": tactics, "techniques": techniques})
        return found

    def detections_list(self):
        with self.lock:
            rules = self.rows("""SELECT rule_id, any_value(rule_title) AS title, any_value(level) AS level,
                    any_value(level_rank) AS level_rank, any_value(tactics) AS tactics,
                    any_value(technique_ids) AS techniques, count(DISTINCT source_record) AS events
                FROM detections GROUP BY rule_id ORDER BY level_rank DESC, events DESC, title""")
        for rule in rules:
            del rule["level_rank"]
        return {"run": self.suzaku_run, "rules": rules}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, store, **kwargs):
        self.store = store
        super().__init__(*args, directory=str(ROOT / "static"), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        super().end_headers()

    def allowed(self):
        # Loopback-only plus Host/Origin checks prevent DNS rebinding and cross-site requests.
        host = self.headers.get("Host", "")
        allowed_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        origin = self.headers.get("Origin")
        if host not in allowed_hosts or (origin and origin not in {"http://" + h for h in allowed_hosts}):
            self.respond({"error": "Only local, same-origin access is allowed"}, 403)
            return False
        return True

    def respond(self, value, status=200):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def mcp_request(self):
        transport = getattr(self.server, "mcp_request", None)
        if transport is None:
            self.respond({"error": "HTTP MCP is disabled; use the stdio adapter"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1048576 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Request must contain at most 1 MB of JSON with Content-Length")
        except ValueError as error:
            self.respond({"error": str(error)}, 400)
            return
        response = transport(self.command, self.path, dict(self.headers), self.rfile.read(length))
        self.send_response(response.status_code)
        for name, value in response.headers.items():
            if name.lower() not in ("content-length", "transfer-encoding", "connection"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)

    def do_DELETE(self):
        if not self.allowed():
            return
        if urlsplit(self.path).path == "/mcp":
            self.mcp_request()
        else:
            self.respond({"error": "Not found"}, 404)

    def do_GET(self):
        if not self.allowed():
            return
        path = urlsplit(self.path).path
        if path == "/mcp":
            self.mcp_request()
        elif path == "/api/meta":
            self.respond(self.store.meta)
        elif path == "/api/reviews":
            self.respond(self.store.reviews_list())
        elif path == "/api/detections":
            self.respond(self.store.detections_list())
        elif path.startswith("/api/events/"):
            try:
                record = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self.respond({"error": "Invalid record ID"}, 400)
                return
            detail = self.store.detail(record)
            self.respond(detail or {"error": "Event not found"}, 200 if detail else 404)
        elif path.startswith("/api/"):
            self.respond({"error": "Not found"}, 404)
        elif path in ("/", "/index.html", "/app.js", "/app.css", "/favicon.png", "/konami-duck.png") or path.startswith("/vendor/"):
            super().do_GET()
        else:
            self.respond({"error": "Not found"}, 404)

    def do_POST(self):
        if not self.allowed():
            return
        if urlsplit(self.path).path == "/mcp":
            self.mcp_request()
            return
        if self.path not in ("/api/meta", "/api/events", "/api/histogram", "/api/column-values", "/api/reviews", "/api/ssm", "/api/ssm-sheet", "/api/ssm-detail", "/api/ssm-event", "/api/ssm-log", "/api/ssm-log-review"):
            self.respond({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1048576:
                raise ValueError("Request must contain at most 1 MB of JSON")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object")
            operation = {"/api/meta": self.store.timezone_metadata, "/api/events": self.store.query, "/api/histogram": self.store.histogram,
                         "/api/column-values": self.store.column_values, "/api/reviews": self.store.review_write,
                         "/api/ssm-log": self.store.ssm_log, "/api/ssm-log-review": self.store.ssm_log_review,
                         "/api/ssm": self.store.commands.list, "/api/ssm-detail": self.store.commands.detail,
                         "/api/ssm-event": self.store.commands.event, "/api/ssm-sheet": self.store.commands.sheet}[self.path]
            self.respond(operation(body))
        except StaleSelection as error:
            self.respond({"error": str(error), "stale": True}, 409)
        except (ValueError, TypeError, AttributeError) as error:
            self.respond({"error": str(error)}, 400)
        except (duckdb.Error, sqlite3.Error) as error:
            self.log_error("Database operation failed: %s", error)
            self.respond({"error": "Database operation failed; check the server log"}, 500)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace serve", description=__doc__)
    parser.add_argument("--database", type=Path, required=True, help="Evidence DuckDB built by `kamotrace import`")
    parser.add_argument("--enrichment", type=Path,
                        help="IP enrichment from `kamotrace enrich` (default: <database>.enrichment.duckdb if present)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--mcp-transport", choices=("http", "stdio"), default="http",
                        help="MCP over HTTP at /mcp (default), or setup instructions for the local stdio adapter")
    # Containers must listen on all interfaces so Docker can publish the port; the image sets
    # KAMOTRACE_BIND=0.0.0.0 and the README publishes it on the host's 127.0.0.1 only.
    parser.add_argument("--bind", default=os.environ.get("KAMOTRACE_BIND", "127.0.0.1"),
                        help="Listening address (default: 127.0.0.1, or $KAMOTRACE_BIND inside the container)")
    parser.add_argument("--annotations", type=Path, help="SQLite sidecar (default: beside the evidence database)")
    parser.add_argument("--ssm-export", type=Path, help="Local ssm_command_session_activity[.enriched].json export")
    parser.add_argument("--detections", type=Path,
                        help="Suzaku detections from `kamotrace suzaku` (default: <database>.detections.duckdb if present)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S%z")
    started = time.monotonic()
    logger.info("Starting KamoTrace; loading local data before accepting requests")
    for name in ("database", "enrichment", "ssm_export", "detections"):
        path = getattr(args, name)
        if path is not None and not path.is_file():
            parser.error(f"--{name.replace('_', '-')} not found: {path}")
    try:
        store = Store(args.database.resolve(), args.enrichment and args.enrichment.resolve(), args.annotations,
                      args.ssm_export, args.detections and args.detections.resolve())
    except ValueError as error:  # e.g. a sidecar built for different evidence, or an invalid SSM export
        parser.error(str(error))
    logger.info("Binding HTTP server to %s:%s", args.bind, args.port)
    server = ThreadingHTTPServer((args.bind, args.port), partial(Handler, store=store))
    if args.bind != "127.0.0.1":
        print(f"Listening on {args.bind}:{args.port}: anyone who can reach this port gets unauthenticated "
              f"access. Publish it only as 127.0.0.1:{args.port}:{args.port}.", flush=True)
    detections = (f" | {store.suzaku_run['linked_rows']:,} Suzaku detections" if store.suzaku_run else "")
    try:
        with ExitStack() as transports:
            base = f"http://127.0.0.1:{server.server_port}"
            if args.mcp_transport == "http":
                from .mcp_server import http_transport
                server.mcp_request = transports.enter_context(http_transport(base))
                setup = (f"MCP (HTTP): {base}/mcp\nConnect your agent using this URL, or run:\n"
                         f"  amp mcp add kamotrace {base}/mcp\n"
                         f"  claude mcp add --transport http kamotrace {base}/mcp")
            else:
                setup = ("MCP (stdio): add the local adapter to your agent (keep this server running):\n"
                         f"  amp mcp add kamotrace -- kamotrace mcp --url {base}\n"
                         f"  claude mcp add kamotrace -- kamotrace mcp --url {base}")
            logger.info("Startup complete in %.1fs", time.monotonic() - started)
            print(f"KamoTrace: {base} | {store.meta['total']:,} events{detections} | read-only", flush=True)
            print(setup, flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.reviews.close()
        store.connection.close()


if __name__ == "__main__":
    main()
