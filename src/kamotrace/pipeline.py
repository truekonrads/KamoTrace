"""Versioned, grammar-only event filters. SQL fragments are application-owned."""
import json

from lark import Lark, Tree, UnexpectedInput


SCALARS = {
    "event_name": ("Operation", "CloudTrail event operation name"),
    "event_source": ("AWS service", "CloudTrail event source service"),
    "identity": ("Identity", "Event principal identity"),
    "source_ip": ("Source IP", "Event source IP address"),
    "country": ("Country", "Offline IP country lookup"),
    "key_id": ("Access key ID", "Principal access key identifier"),
    "target": ("Target instance", "Target instance identifier"),
    "error_code": ("Error code", "CloudTrail error code"),
    "identity_type": ("Identity type", "Principal identity type"),
    "region": ("Region", "AWS event region"),
    "user_agent": ("User agent", "Event user agent text"),
    "event_id": ("Event ID", "CloudTrail event identifier"),
    "document_name": ("SSM document", "SSM document name"),
    "isp": ("Network / ISP", "Offline IP network organization lookup"),
    "city": ("City", "Offline IP city lookup"),
    "asn": ("ASN", "Offline IP autonomous system number"),
    "ip_info": ("IP attributes", "Offline IP enrichment attributes"),
}
SCALAR_OPS = ["=", "!=", "in", "contains", "is missing", "is not missing", "is empty", "is not empty"]
FIELDS = {key: {"label": label, "description": description, "operators": SCALAR_OPS[:]}
          for key, (label, description) in SCALARS.items()}
FIELDS.update({key: {"label": label, "description": description, "operators": ["=", "!=", "in"]}
               for key, label, description in (
                   ("tag", "Event tag", "Exact event tag slug membership"),
                   ("lead", "Lead", "Exact evidence-linked rule/context ID membership"))})

PARSER = Lark(r'''
    query: [expr ("|" expr)*]
    ?expr: conjunction (_OR conjunction)* -> either
    ?conjunction: unary (_AND unary)* -> both
    ?unary: _NOT unary -> negate
          | "(" expr ")" -> group
          | predicate
    ?predicate: _SEARCH STRING -> search
              | FIELD "=" STRING -> eq
              | FIELD "!=" STRING -> neq
              | FIELD _CONTAINS STRING -> contains
              | FIELD _IN "(" STRING ("," STRING)* ")" -> member
              | FIELD _IS _MISSING -> missing
              | FIELD _IS _NOT _MISSING -> not_missing
              | FIELD _IS _EMPTY -> empty
              | FIELD _IS _NOT _EMPTY -> not_empty
    _OR.2: /(?i:or)\b/
    _AND.2: /(?i:and)\b/
    _NOT.2: /(?i:not)\b/
    _SEARCH.2: /(?i:search)\b/
    _CONTAINS.2: /(?i:contains)\b/
    _IN.2: /(?i:in)\b/
    _IS.2: /(?i:is)\b/
    _MISSING.2: /(?i:missing)\b/
    _EMPTY.2: /(?i:empty)\b/
    FIELD: /[a-zA-Z_][a-zA-Z_0-9]*/
    STRING: /"(?:[^"\\\x00-\x1f]|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"/
    %import common.WS
    %ignore WS
''', start="query", parser="lalr", lexer="basic", propagate_positions=True, maybe_placeholders=False)


def _utf16_length(text):
    """Browser selection and slice offsets use UTF-16 code units, not code points."""
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2


class PipelineError(ValueError):
    def __init__(self, message, source="", start=0, end=None):
        start = max(0, min(len(source), start))
        end = min(len(source), start + 1) if end is None else end
        self.start = _utf16_length(source[:start])
        self.end = _utf16_length(source[:end])
        self.line = source.count("\n", 0, start) + 1
        self.column = _utf16_length(source[source.rfind("\n", 0, start) + 1:start]) + 1
        super().__init__(f"{message} (line {self.line}, column {self.column})")

    def response(self):
        return {"error": str(self), "line": self.line, "column": self.column,
                "start": self.start, "end": self.end}


def parse(body):
    """Validate all syntax and semantics before compiling any SQL."""
    source = body.get("pipeline")
    if type(body.get("pipeline_version")) is not int or body["pipeline_version"] != 1:
        raise PipelineError("Unsupported pipeline_version; expected 1")
    if not isinstance(source, str):
        raise PipelineError("Pipeline must be text")
    if len(source) > 8000:
        raise PipelineError("Pipeline exceeds 8,000 characters", source, 8000)

    def fail(message, node):
        meta = node.meta if isinstance(node, Tree) else node
        raise PipelineError(message, source, meta.start_pos, meta.end_pos)

    try:
        # Bound nesting before the grammar parser sees it. Each frame retains
        # NOTs enclosing a group; Boolean separators reset only the current frame.
        frames = [0]
        list_depth = False
        previous = None
        stages = 1
        for token in PARSER.lex(source):
            kind = token.type
            if kind == "_NOT" and previous != "_IS":
                frames[-1] += 1
            elif kind == "LPAR":
                if previous == "_IN":
                    list_depth = True
                else:
                    frames.append(0)
            elif kind == "RPAR":
                if list_depth:
                    list_depth = False
                elif len(frames) > 1:
                    frames.pop()
            elif kind in ("_OR", "_AND", "VBAR"):
                frames[-1] = 0
                if kind == "VBAR":
                    stages += 1
                    if stages > 20:
                        fail("Use at most 20 stages", token)
            if len(frames) - 1 + sum(frames) > 20:
                fail("Use at most 20 nested parentheses/NOT operators", token)
            previous = kind
        tree = PARSER.parse(source)
    except UnexpectedInput as error:
        start = len(source) if getattr(getattr(error, "token", None), "type", None) == "$END" else error.pos_in_stream
        raise PipelineError("Invalid pipeline syntax; expected a predicate or Boolean operator",
                            source, start) from None

    predicates = 0
    pending = [(tree, 0)]
    while pending:
        node, depth = pending.pop()
        depth += node.data in ("negate", "group")
        if depth > 20:
            fail("Use at most 20 nested parentheses/NOT operators", node)
        pending.extend((child, depth) for child in reversed(node.children) if isinstance(child, Tree))
        if node.data in ("query", "either", "both", "negate", "group"):
            continue
        predicates += 1
        if predicates > 100:
            fail("Use at most 100 predicates", node)
        if node.data != "search":
            field = str(node.children[0])
            if field not in FIELDS:
                fail("Unknown pipeline field", node.children[0])
            if field in ("tag", "lead") and node.data not in ("eq", "neq", "member"):
                fail("Tag and lead support only =, != and in", node)
        values = node.children if node.data == "search" else node.children[1:]
        if len(values) > 100:
            fail("Use at most 100 values per in list", node)
        for token in values:
            value = json.loads(str(token))
            if len(value) > 2000:
                fail("Strings must contain at most 2,000 decoded characters", token)
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                fail("Unpaired Unicode surrogates are not allowed", token)
    return source, tree


def _sole(node):
    while node.data in ("either", "both") and len(node.children) == 1:
        node = node.children[0]
    return node


def describe(body):
    source, tree = parse(body)
    stages = []
    for stage in tree.children:
        node = _sole(stage)
        fields = list(dict.fromkeys(str(n.children[0]) for n in stage.iter_subtrees_topdown()
                                   if n.data not in ("either", "both", "group", "negate", "search")))
        shortcut = node.data in ("eq", "member") and str(node.children[0]) in ("tag", "lead")
        stages.append({"start": _utf16_length(source[:stage.meta.start_pos]),
                       "end": _utf16_length(source[:stage.meta.end_pos]), "fields": fields,
                       "field": str(node.children[0]) if shortcut else None,
                       "values": [json.loads(str(t)) for t in node.children[1:]] if shortcut else None})
    single = _sole(tree.children[0]) if len(tree.children) == 1 else None
    search = "" if not tree.children else (json.loads(str(single.children[0]))
              if single is not None and single.data == "search" else None)
    return {"stages": stages, "search": search}


def compile_pipeline(body):
    _, tree = parse(body)
    params = []

    def compile_node(node):
        kind, children = node.data, node.children
        if kind in ("query", "both", "either"):
            if not children:
                return "TRUE"
            joiner = " OR " if kind == "either" else " AND "
            return "(" + joiner.join(map(compile_node, children)) + ")"
        if kind in ("negate", "group"):
            return ("NOT " if kind == "negate" else "") + "(" + compile_node(children[0]) + ")"
        if kind == "search":
            value = json.loads(str(children[0]))
            params.extend([value, json.dumps(value, ensure_ascii=False)[1:-1]])
            return "coalesce((contains(lower(raw_event::VARCHAR), lower(?)) OR contains(lower(raw_event::VARCHAR), lower(?))), FALSE)"
        field = str(children[0])
        values = [json.loads(str(t)) for t in children[1:]]
        if kind in ("missing", "not_missing"):
            return f"{field} IS {'NOT ' if kind == 'not_missing' else ''}NULL"
        if kind in ("empty", "not_empty"):
            return f"coalesce({field}, '') {'<>' if kind == 'not_empty' else '='} ''"
        params.extend(values)
        if field in ("tag", "lead"):
            column, table, key, outer = (("slug", "review_tags", "hash", "record_sha256")
                                         if field == "tag" else ("rule_id", "detections", "source_record", "id"))
            sql = f"{outer} IN (SELECT {key} FROM {table} WHERE {column} IN ({', '.join('?' for _ in values)}))"
            return ("NOT " if kind == "neq" else "") + f"coalesce(({sql}), FALSE)"
        if kind in ("eq", "neq"):
            return f"{field} IS {'NOT ' if kind == 'eq' else ''}DISTINCT FROM ?"
        if kind == "member":
            return f"coalesce({field} IN ({', '.join('?' for _ in values)}), FALSE)"
        return f"coalesce(contains(lower({field}), lower(?)), FALSE)"

    return compile_node(tree), params
