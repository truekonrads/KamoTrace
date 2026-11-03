"""Bounded JSON scalar paths: application-owned aliases, parameter-bound paths."""
import re
import json


class Number(str):
    """Keep a JSON number's exact lexeme, distinguishable from a JSON string."""


def scalar(raw, field):
    value = json.loads(raw, parse_int=Number, parse_float=Number)
    for part in re.findall(r"[A-Za-z_][A-Za-z_0-9]*|\[[0-9]+\]", field[4:]):
        if part.startswith("["):
            index = int(part[1:-1])
            if not isinstance(value, list) or index >= len(value):
                return {"value": None, "json_type": None}
            value = value[index]
        elif not isinstance(value, dict) or part not in value:
            return {"value": None, "json_type": None}
        else:
            value = value[part]
    kind = ("NULL" if value is None else "NUMBER" if isinstance(value, Number) else
            "STRING" if isinstance(value, str) else "BOOLEAN" if isinstance(value, bool) else
            "ARRAY" if isinstance(value, list) else "OBJECT")
    text = str(value) if kind in ("NUMBER", "STRING") else ("true" if value else "false") if kind == "BOOLEAN" else None
    return {"value": text, "json_type": kind}

PATH = re.compile(r"raw\.[A-Za-z_][A-Za-z_0-9]*(?:(?:\.[A-Za-z_][A-Za-z_0-9]*)|(?:\[(?:0|[1-9][0-9]{0,3})\]))*\Z")
CONTRACT = {"prefix": "raw.", "example": "raw.requestParameters.name", "max_length": 256,
            "max_depth": 8, "max_index": 1000, "max_fields": 10,
            "value": "Unquoted scalar text, including exact numeric text; no numeric coercion or range operators",
            "missing": "Missing, JSON null and containers have no scalar value; missing/empty operators use that null",
            "projection": "raw_fields maps requested paths to value and json_type; absent type is null, JSON null is NULL, containers retain OBJECT/ARRAY",
            "sorting": "Lexicographic scalar text, not numeric order", "pipeline": "Use ordinary filters, not pipeline v1 field syntax"}


def fields(body):
    projected = body.get("raw_fields", [])
    if not isinstance(projected, list) or len(projected) > 10:
        raise ValueError("raw_fields must contain at most 10 constrained raw scalar paths")
    used = [*projected, *[f.get("field") for f in body.get("filters", []) if isinstance(f, dict)],
            *[s.get("field") for s in body.get("sorters", []) or [] if isinstance(s, dict)], body.get("field")]
    result = {}
    for field in used:
        if field in projected and not isinstance(field, str):
            raise ValueError("raw_fields must contain constrained raw scalar path strings")
        if isinstance(field, str) and (field.startswith("raw.") or field in projected):
            if (len(field) > 256 or not PATH.fullmatch(field) or field.count(".") + field.count("[") > 8
                    or any(int(index) > 1000 for index in re.findall(r"\[([0-9]+)\]", field))):
                raise ValueError("Invalid raw scalar path; use raw.key.child[0], ≤256 characters, depth ≤8, indices 0–1000")
            result.setdefault(field, "__raw_" + str(len(result)))
    if len(result) > 10:
        raise ValueError("Use at most 10 distinct raw scalar fields across projection, filters, summaries and sorting")
    return result
