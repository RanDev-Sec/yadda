"""yaral - parses the events: section of a YARA-L rule into a boolean tree of field predicates, and works out what
a rule can match on (event types, log types, product event types)."""
from __future__ import annotations

import functools
import re


# ---------------------------------------------------------------- depth: data paths each rule reads
PET_RE = re.compile(r'metadata\.product_event_type\s*=\s*(?:"([^"]+)"|/([^/]+)/)')


YL_VALUE = r'(?:/(?:\\.|[^/\\])*/(?:\s*nocase)?|"(?:\\.|[^"\\])*"(?:\s*nocase)?|`[^`]*`|%\w+|-?[\w.$:]+)'


_F = r'(?P<field>[\w.]+(?:\[[^\]]*\])?(?:\.[\w.]+)?)'


_WRAP_OPEN, _WRAP_CLOSE = r'(?:[\w.]+\(\s*)*', r'\s*(?:\)\s*)*'


YL_PRED = re.compile(r'(?<![\w.])' + _WRAP_OPEN + r'\$(?P<var>\w+)\.' + _F + _WRAP_CLOSE + r'(?P<op>!=|=|>=|<=|>|<|\bin\b)\s*(?P<val>' + YL_VALUE + ')', re.I)


YL_FUNC = re.compile(r'(?P<fn>re\.regex|strings\.\w+|net\.\w+)\s*\(\s*' + _WRAP_OPEN + r'\$(?P<var>\w+)\.' + _F + _WRAP_CLOSE + r',\s*(?P<val>' + YL_VALUE + ')', re.I)


YL_ASSIGN = re.compile(r'\$(?P<var>\w+)\.' + _F + r'\s*=\s*\$(?P<ph>\w+)\b(?!\.)')


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, but not '//' inside strings or regexes (e.g. "http://x")."""
    out, i, quote, n = [], 0, None, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if ch == quote or (ch == "\n" and quote != "`"):
                quote = None
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        elif ch in "\"'`":
            quote = ch; out.append(ch)
        elif ch == "/" and re.search(r"(=|!=|,|\(|\bin)\s*$", "".join(out[-20:])):
            quote = "/"; out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _yl_events(text: str) -> str:
    m = re.search(r"^\s*events:\s*$(.*?)(?=^\s*(?:match|outcome|condition|options):\s*$|^\}|\Z)", text, re.S | re.M)
    body = _strip_comments(m.group(1) if m else "")
    # $e.target.application = $svc ... $svc in %list  ->  the list filter is really on $e.target.application
    for m in YL_ASSIGN.finditer(body):
        body = re.sub(r"(?<![\w.])\$" + m.group("ph") + r"\b(?!\.)(?!\s*=\s*\$)", f"${m.group('var')}.{m.group('field')}", body)
    return body


def _split_top(text: str, word: str) -> list[str]:
    """Split on a boolean keyword at bracket depth 0 (ignores the keyword inside strings, regexes and brackets)."""
    parts, depth, cur, i, quote = [], 0, [], 0, None
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1]); i += 2; continue
            if ch == quote:
                quote = None
        elif ch in "\"`":
            quote = ch; cur.append(ch)
        elif ch == "/" and re.search(r"(=|!=|,|\()\s*$", "".join(cur)):
            quote = "/"; cur.append(ch)
        elif ch in "([":
            depth += 1; cur.append(ch)
        elif ch in ")]":
            depth -= 1; cur.append(ch)
        elif depth == 0 and re.match(rf"\s{word}\s", text[i:i + len(word) + 2], re.I):
            parts.append("".join(cur)); cur = []; i += len(word) + 1; continue
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _outer(t: str):
    """'( ... )' -> inner text when the first bracket closes at the very end; otherwise None."""
    t = t.strip()
    if not t.startswith("("):
        return None
    depth = 0
    for i, ch in enumerate(_strip_literals(t)):
        depth += (ch == "(") - (ch == ")")
        if depth == 0:
            return t[1:-1].strip() if i == len(t) - 1 else None
    return None


def _strip_literals(t: str) -> str:
    """Same-length copy with the inside of "strings", `regexes` and /regexes/ masked, so brackets inside them
    aren't counted and positions still line up with the original text."""
    mask = lambda m: m.group(1) + m.group(2)[0] + "x" * (len(m.group(2)) - 2) + m.group(2)[-1]
    t = re.sub(r'()("(?:\\.|[^"\\])*"|`[^`]*`)', mask, t)
    return re.sub(r'((?:=|!=|,|\()\s*)(/(?:\\.|[^/\\])*/)', mask, t)


def _yl_statements(events: str) -> list[str]:
    """Top-level statements of an events: section (YARA-L AND-s them implicitly, one per line)."""
    out, buf, depth = [], [], 0
    for line in events.splitlines():
        t = line.strip()
        if not t:
            continue
        joins = re.match(r"(and|or)\b", t, re.I) or (buf and re.search(r"\b(and|or)$", buf[-1], re.I))
        if buf and depth == 0 and not joins:
            out.append(" ".join(buf))
            buf = []
        buf.append(t)
        lit = _strip_literals(t)
        depth += lit.count("(") - lit.count(")")
    if buf:
        out.append(" ".join(buf))
    return out


def _yl_tree(t: str):
    """Boolean tree: ("and"|"or", [children]) / ("not", child) / ("pred", predicate) / None."""
    t = t.strip()
    if not t:
        return None
    parts = _split_top(" " + t + " ", "or")
    if len(parts) > 1:
        kids = [k for k in (_yl_tree(p) for p in parts) if k]
        return ("or", kids) if len(kids) > 1 else (kids[0] if kids else None)
    parts = _split_top(" " + t + " ", "and")
    if len(parts) > 1:
        kids = [k for k in (_yl_tree(p) for p in parts) if k]
        return ("and", kids) if len(kids) > 1 else (kids[0] if kids else None)
    m = re.match(r"not\s*(?=\()", t, re.I)
    if m and _outer(t[m.end():]) is not None:
        k = _yl_tree(_outer(t[m.end():]))
        return ("not", k) if k else None
    if _outer(t) is not None:
        return _yl_tree(_outer(t))
    preds = [p for p in (_yl_pred(x) for x in [*YL_PRED.finditer(t), *YL_FUNC.finditer(t)]) if p]
    if not preds:
        return None
    leaves = [("pred", p) for p in preds]
    return leaves[0] if len(leaves) == 1 else ("and", leaves)


def _yl_events_tree(events: str):
    kids = [k for k in (_yl_tree(st) for st in _yl_statements(events)) if k]
    return ("and", kids) if len(kids) > 1 else (kids[0] if kids else None)


def _tree_map(node, fn):
    """Rebuild a tree, replacing each predicate leaf with fn(pred) -> node | True | False | None (None = drop)."""
    if node is None:
        return None
    kind = node[0]
    if kind == "pred":
        return fn(node[1])
    if kind == "not":
        k = _tree_map(node[1], fn)
        return (not k) if isinstance(k, bool) else (("not", k) if k is not None else None)
    raw = [_tree_map(k, fn) for k in node[1]]
    if kind == "and":
        if any(k is False for k in raw):
            return False
        kids = [k for k in raw if k is not None and k is not True]
        if not kids:
            return True if any(k is True for k in raw) else None
    else:
        if any(k is True for k in raw):
            return True
        kids = [k for k in raw if k is not None and k is not False]
        if not kids:
            return False if any(k is False for k in raw) else None
    return kids[0] if len(kids) == 1 else (kind, kids)


def _tree_preds(node) -> list:
    if not node or isinstance(node, bool):
        return []
    if node[0] == "pred":
        return [node[1]]
    if node[0] == "not":
        return _tree_preds(node[1])
    return [p for k in node[1] for p in _tree_preds(k)]


def _yl_pred(m) -> dict | None:
    val = m.group("val").strip()
    if val.startswith("$"):
        return None                                           # placeholder or join between event variables, not a filter
    neg = (m.groupdict().get("op") == "!=") != bool(re.search(r"\bnot\s*$", m.string[max(0, m.start() - 6):m.start()], re.I))
    regex = val.startswith("/") or m.groupdict().get("fn", "") == "re.regex" or val.startswith("`")
    clean = re.sub(r"\s*nocase$", "", val).strip()
    clean = clean[1:clean.rfind("/")] if clean.startswith("/") else clean.strip('"`')
    field = re.sub(r'\[\s*"([^"]+)"\s*\]', r".\1", m.group("field"))      # additional.fields["X"] -> additional.fields.X
    return {"var": m.group("var"), "field": re.sub(r"\[[^\]]*\]", "", field), "neg": neg,
            "value": clean, "regex": regex, "list": val.startswith("%")}


LOGTYPE_RE = re.compile(r'metadata\.log_type\s*=\s*(?:"([^"]+)"|/([^/]+)/)')


EVTYPE_RE = re.compile(r'metadata\.event_type\s*=\s*"([A-Z_]+)"')


def _live_preds(node, negated=False):
    """Predicates with their effective polarity: (pred, is_negated), following not(...) groups."""
    if node is None or isinstance(node, bool):
        return []
    kind = node[0]
    if kind == "pred":
        return [(node[1], negated != node[1]["neg"])]
    if kind == "not":
        return _live_preds(node[1], not negated)
    return [x for k in node[1] for x in _live_preds(k, negated)]


def _values(p) -> set:
    """A predicate's value(s); a regex alternation like /PROCESS_LAUNCH|PROCESS_OPEN/ gives each alternative."""
    v = p["value"]
    if p.get("list"):
        return set()                                          # reference list (%name): contents not known here
    if p["regex"]:
        return {x.strip("^$() ") for x in v.split("|") if x.strip("^$() ") and not re.search(r"[.*+?\[\]{}\\]", x.strip("^$() "))}
    return {v} if v else set()


def scope(text: str) -> dict:
    """scope() of a rule text, parsed once per run however many outputs ask (callers get their own sets)."""
    return {k: set(v) for k, v in _scope_cached(text).items()}


@functools.lru_cache(maxsize=4096)
def _scope_cached(text: str) -> dict:
    return _scope(text)


def _scope(text: str) -> dict:
    """What a rule can match on, from its live events: logic only (comments, meta, outcome and negated
    filters don't count): {'event_types', 'log_types', 'product_event_types'} as sets."""
    out = {"event_types": set(), "log_types": set(), "product_event_types": set()}
    keys = {"metadata.event_type": "event_types", "metadata.log_type": "log_types",
            "metadata.product_event_type": "product_event_types"}
    for p, negated in _live_preds(_yl_events_tree(_yl_events(text))):
        k = keys.get(p["field"])
        if k and not negated:
            vals = _values(p)
            out[k] |= {v.upper() for v in vals} if k != "product_event_types" else vals
    return out
