"""Disposable immutable exports, privately staged and addressed only by opaque IDs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time

from .importer import publish, staging, write_lock

MAX_ROWS = 50000
MAX_BYTES = 32 * 1024 * 1024
MAX_ARTIFACTS = 4  # Prepared content plus the single staging file never exceed 128 MiB.
TTL_SECONDS = 600


class Exports:
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="kamotrace-exports-")
        self.root = Path(self.directory.name)
        self.lock = threading.Lock()
        self.preparing = threading.BoundedSemaphore(1)
        self.artifacts = {}

    def cleanup(self):
        """Caller holds registry lock. Only registry-owned disposable files can be deleted."""
        for token, artifact in list(self.artifacts.items()):
            if artifact["expires"] <= time.time():
                try:
                    artifact["path"].unlink(missing_ok=True)
                except PermissionError:  # Windows may still have an active download; retry next request.
                    continue
                del self.artifacts[token]

    def prepare(self, writer, base_url):
        if not self.preparing.acquire(blocking=False):
            raise ValueError("An export is already preparing; retry after it completes")
        output = None
        try:
            with self.lock:
                self.cleanup()
                if len(self.artifacts) >= MAX_ARTIFACTS:
                    raise ValueError("Export disk quota reached (4 artifacts / 128 MiB); wait for expiry")
            token = secrets.token_hex(16)
            output = self.root / (token + ".ndjson")
            digest, size, rows = hashlib.sha256(), 0, 0
            with write_lock(output), staging(output) as staged:
                with staged.open("xb") as stream:
                    def emit(value):
                        nonlocal size, rows
                        # Reject enormous strings before allocating an escaped/encoded copy.
                        pending, characters = [value], 0
                        while pending:
                            part = pending.pop()
                            if isinstance(part, str):
                                characters += len(part)
                                if characters > MAX_BYTES - size:
                                    raise ValueError("Export exceeds 32 MiB; narrow the selection or fields")
                            elif isinstance(part, dict):
                                pending.extend(part.values())
                            elif isinstance(part, (list, tuple)):
                                pending.extend(part)
                        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                        if size + len(encoded) > MAX_BYTES:
                            raise ValueError("Export exceeds 32 MiB; narrow the selection or fields")
                        if value["type"] != "manifest":
                            rows += 1
                            if rows > MAX_ROWS:
                                raise ValueError("Export exceeds 50,000 rows; narrow the selection")
                        stream.write(encoded)
                        digest.update(encoded)
                        size += len(encoded)
                    writer(emit)
                    stream.flush()
                    os.fsync(stream.fileno())
                publish(staged, output)
            expires = time.time() + TTL_SECONDS
            info = {"id": token, "ready": True, "rows": rows, "bytes": size, "sha256": digest.hexdigest(),
                "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                "download_url": base_url.rstrip("/") + "/api/exports/" + token,
                "reachability": "Loopback URLs work only for clients on the server machine. Use bounded text reads if download is unreachable."}
            with self.lock:
                self.artifacts[token] = {"path": output, "expires": expires, "info": info}
            return info
        finally:
            if output is not None:
                output.with_suffix(".lock").unlink(missing_ok=True)
            self.preparing.release()

    def open(self, token):
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return None
        with self.lock:
            self.cleanup()
            artifact = self.artifacts.get(token)
            if artifact is None or artifact["expires"] <= time.time():
                return None
            # Open before releasing the registry lock; a slow download owns its handle,
            # not the Store lock. Expiry cannot substitute content underneath it.
            return artifact["path"].open("rb"), artifact["info"]

    def close(self):
        self.directory.cleanup()
