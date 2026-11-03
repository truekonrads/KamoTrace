"""Conservative, bounded, inert text derivation. No execution, fetching or decompression."""
import base64
import binascii
import re
import unicodedata

VERSION = "local-base64-v1"
LIMITS = {"input_code_points": 65536, "candidate_code_points": 16384, "candidates": 32,
          "depth": 2, "output_bytes": 16384, "source_nodes": 512,
          "case_input_code_points": 16 * 1024 * 1024, "case_candidates": 4096,
          "case_output_bytes": 1024 * 1024, "case_entries": 10000}
TOKEN = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")  # Linear token scan over bounded input, not a user pattern.


def candidates(text):
    """Return contiguous spans, joining only line-wrapped tokens, not adjacent command words."""
    pending = None
    for match in TOKEN.finditer(text):
        start, end = match.span()
        if pending is not None:
            gap = text[pending[1]:start]
            if (end - start >= 4 and not text[pending[0]:pending[1]].endswith("=")
                    and "\n" in gap and len(gap) <= 16 and gap.isspace()):
                pending = (pending[0], end)
                continue
            yield pending
            pending = None
        if end - start >= 16:
            pending = (start, end)
    if pending is not None:
        yield pending


def decode(encoded):
    compact = "".join(encoded.split())
    if (len(compact) > LIMITS["candidate_code_points"] or len(compact) % 4 == 1
            or re.fullmatch(r"[a-fA-F0-9]+", compact)
            or compact.startswith(("AKIA", "ASIA", "AIDA", "AROA", "i-", "ami-"))):
        return None
    alphabet = "urlsafe" if "-" in compact or "_" in compact else "standard"
    if alphabet == "urlsafe" and ("+" in compact or "/" in compact):
        return None
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    canonical = base64.urlsafe_b64encode(raw) if alphabet == "urlsafe" else base64.b64encode(raw)
    if canonical.decode().rstrip("=") != compact.rstrip("="):
        return None
    encodings = ["utf-8"] + (["utf-16-le"] if len(raw) % 2 == 0 and raw.count(b"\0") > len(raw) // 4 else [])
    for encoding in encodings:
        try:
            text = raw.decode(encoding)
        except UnicodeError:
            continue
        if (len(text) >= 8 and any(c.isalpha() for c in text)
                and any(not c.isalnum() for c in text)
                and all(c in "\t\n\r" or not unicodedata.category(c).startswith("C") for c in text)):
            return text, encoding, alphabet
    return None


class Analysis:
    def __init__(self):
        self.scanned = self.attempted = self.output = self.entries = 0
        self.parameter_cache = {}

    def analyze(self, inputs):
        self.entries += 1
        rows, reasons = [], set()
        scanned = attempted = output = nodes = 0

        def scan(text, field, parent=None, depth=0):
            nonlocal scanned, attempted, output
            remaining = min(LIMITS["input_code_points"] - scanned,
                            LIMITS["case_input_code_points"] - self.scanned)
            prefix = text[:max(0, remaining)]
            if len(prefix) < len(text):
                reasons.add("input_limit" if scanned + len(prefix) >= LIMITS["input_code_points"] else "case_input_limit")
            if not prefix:
                return
            key = (field, prefix)
            spans = self.parameter_cache.get(key) if field.startswith("parameters") and parent is None else None
            scanned += len(prefix)
            self.scanned += len(prefix)
            if spans is None:
                spans = []
                for span in candidates(prefix):
                    spans.append(span)
                    if len(spans) > LIMITS["candidates"]:
                        break
                if field.startswith("parameters") and parent is None and len(self.parameter_cache) < 128:
                    self.parameter_cache[key] = spans
            for start, end in spans:
                if depth >= LIMITS["depth"]:
                    reasons.add("depth_limit")
                    break
                if attempted >= LIMITS["candidates"] or self.attempted >= LIMITS["case_candidates"]:
                    reasons.add("candidate_limit" if attempted >= LIMITS["candidates"] else "case_candidate_limit")
                    break
                attempted += 1
                self.attempted += 1
                if end - start > LIMITS["candidate_code_points"]:
                    reasons.add("candidate_size_limit")
                    continue
                original = prefix[start:end]
                decoded = decode(original)
                if decoded is None:
                    continue
                text_value, encoding, alphabet = decoded
                size = len(text_value.encode("utf-8"))
                if output + size > LIMITS["output_bytes"] or self.output + size > LIMITS["case_output_bytes"]:
                    reasons.add("output_limit" if output + size > LIMITS["output_bytes"] else "case_output_limit")
                    continue
                output += size
                self.output += size
                index = len(rows)
                rows.append({"id": index, "parent": parent, "source_field": field, "start": start, "end": end,
                    "offset_unit": "unicode_code_points", "original_text": original, "text": text_value,
                    "encoding": encoding, "alphabet": alphabet, "source": "local_base64", "decoder_version": VERSION})
                scan(text_value, field, index, depth + 1)

        if self.entries > LIMITS["case_entries"]:
            reasons.add("case_entry_limit")
        else:
            stack = [(field, value, 0) for field, value in reversed(inputs)]
            while stack:
                field, value, depth = stack.pop()
                nodes += 1
                if nodes > LIMITS["source_nodes"] or depth > 16 or len(field) > 512:
                    reasons.add("source_structure_limit")
                    break
                if isinstance(value, str):
                    scan(value, field)
                elif isinstance(value, dict):
                    # Bound breadth before extending the traversal stack.
                    for i, (key, part) in enumerate(value.items()):
                        if i >= LIMITS["source_nodes"]:
                            reasons.add("source_structure_limit")
                            break
                        stack.append((field + "." + str(key)[:513], part, depth + 1))
                elif isinstance(value, list):
                    if len(value) > LIMITS["source_nodes"]:
                        reasons.add("source_structure_limit")
                    stack.extend((f"{field}[{i}]", part, depth + 1) for i, part in enumerate(value[:LIMITS["source_nodes"]]))
        return {"decoder_version": VERSION, "derivations": rows, "truncated": bool(reasons),
                "reasons": sorted(reasons), "limits": LIMITS, "scanned_code_points": scanned,
                "candidates": attempted, "output_bytes": output}
