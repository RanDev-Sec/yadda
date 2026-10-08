"""sigma - SigmaHQ rules converted to YARA-L as *candidate* rules for an environment's gaps or threats.

Conversion is done by pySigma with AttackIQ's Google SecOps backend (pySigma-backend-secops, LGPL). That backend
only translates the detection logic reliably: its rule wrapper writes `conditions:` (not valid YARA-L), unescaped
meta strings and rule names with hyphens. So yadda keeps the backend's events: logic and writes its own wrapper.
Rules whose fields the backend can't map to UDM are skipped, never guessed.

Candidates go to output/<environment>/<date>/4_sigma_candidates/ and are not counted as coverage: yadda reads only
rules/ (what is deployed). Deploy the ones you want in SecOps yourself; the next `yadda run` (or `yadda import`) picks them
up like any other rule.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from delib import inputs
from delib.config import HOME, out_dir, TOOLS, _rmtree, envdir, die, read_csv, read_lock, read_text, write_csv, write_text
from delib.yaral import _strip_literals, scope

SIGMA_REPO = TOOLS / "sigma"
RULE_DIRS = ("rules", "rules-emerging-threats")          # rules-threat-hunting is deliberately broad: --hunting adds it
STATUS_OK = {"stable", "test"}                           # --experimental adds experimental
LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# Sigma logsource product/service -> ATT&CK platforms (environment.env PLATFORMS). Unknown products aren't filtered.
PRODUCT_PLATFORMS = {
    "windows": {"Windows"}, "linux": {"Linux"}, "macos": {"macOS"},
    "azure": {"Identity Provider", "IaaS", "Office Suite"}, "m365": {"Office Suite"}, "microsoft365": {"Office Suite"},
    "okta": {"Identity Provider"}, "onelogin": {"Identity Provider"},
    "aws": {"IaaS"}, "gcp": {"IaaS"}, "google_workspace": {"Office Suite", "SaaS"}, "github": {"SaaS"},
    "kubernetes": {"Containers"}, "esxi": {"ESXi"},
    "cisco": {"Network Devices"}, "juniper": {"Network Devices"}, "fortinet": {"Network Devices"},
}


def _top_split(text: str, word: str) -> list[str]:
    """Split on ' and ' / ' or ' outside brackets, strings and regexes."""
    masked, parts, depth, last = _strip_literals(text).lower(), [], 0, 0
    i = 0
    while i < len(masked):
        ch = masked[i]
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and masked.startswith(f" {word} ", i):
            parts.append(text[last:i])
            last = i = i + len(word) + 2
            continue
        i += 1
    return [p.strip() for p in parts + [text[last:]]]


def _unwrap(text: str) -> str:
    """'(x)' -> 'x' when the outer brackets enclose everything."""
    t = text.strip()
    while t.startswith("(") and t.endswith(")"):
        masked, depth = _strip_literals(t), 0
        for i, ch in enumerate(masked):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(t) - 1:
                return t
        t = t[1:-1].strip()
    return t


NEGATE_OP = {"=": "!=", "!=": "=", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def _negate(expr: str) -> str:
    """YARA-L text for NOT expr, pushed down to single comparisons (De Morgan). Raises ValueError if it can't."""
    t = _unwrap(expr)
    for word, other in (("or", "and"), ("and", "or")):
        parts = _top_split(t, word)
        if len(parts) > 1:
            return "(" + f" {other} ".join(_negate(p) for p in parts) + ")"
    if t[:4].lower() == "not ":
        return t[4:]
    if re.match(r"[a-z_]+\.[a-z_]+\(", t):                  # net.ip_in_range_cidr(...), re.regex(...)
        return "not " + t
    masked = _strip_literals(t)
    m = re.match(r"(\$[\w.\[\]\\\"]+)\s*(!=|<=|>=|=|<|>)\s*", masked)
    if not m:
        raise ValueError(f"can't negate: {t[:80]}")
    return f"{t[:m.start(2)].rstrip()} {NEGATE_OP[m.group(2)]} {t[m.end():]}"


def _backend():
    try:
        from sigma.backends.secops import SecOpsBackend
        from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionNOT, ConditionValueExpression
        from sigma.pipelines.secops import secops_udm_pipeline
        from sigma.types import SigmaRegularExpressionFlag
    except ImportError:
        die("the Sigma converter isn't installed - run: yadda setup")

    class Backend(SecOpsBackend):
        """Corrections to pySigma-backend-secops 1.0.0, each one a case where its output matches different events
        than the Sigma rule (yadda doctor re-checks them):
        - `not` over a group is dropped (`sel and not (A and B)` -> `sel and A and B`), and over a number, CIDR,
          comparison or null it isn't applied. yadda negates every NOT itself, down to single comparisons.
        - a multi-value |endswith / |startswith list is folded into one regex without its anchors: lists stay
          one comparison per value.
        - |windash / |base64offset expansions come out as a bare `a or b`, which binds wrongly next to `and`.
        - |re regexes get their backslashes doubled and a forced `nocase`."""

        def decide_convert_condition_as_in_expression(self, cond, state):
            return False

        def convert_condition(self, cond, state, parent_cond=None):
            if isinstance(cond, ConditionNOT):
                inner = cond.args[0]
                if isinstance(inner, ConditionNOT):
                    return self.convert_condition(inner.args[0], state, parent_cond)
                if isinstance(inner, ConditionValueExpression):
                    raise ValueError("keyword search without a field")
                positive = self.convert_condition(inner, state, None)
                return "(" + _negate(positive) + ")"
            if isinstance(parent_cond, ConditionNOT):
                parent_cond = None              # negation is done above; stop the backend's own (partial) attempt
            out = super().convert_condition(cond, state, parent_cond)
            if isinstance(cond, ConditionFieldEqualsValueExpression) and isinstance(out, str) \
                    and len(_top_split(_unwrap(out), "or")) > 1:
                out = "(" + out + ")"
            return out

        def convert_condition_field_eq_val_re(self, cond, state):
            saved = self.re_expression, self.re_escape_escape_char
            self.re_expression = "{field} = /{regex}/"            # Sigma |re is case-sensitive unless |i
            self.re_escape_escape_char = False                      # it's already a regex: keep its backslashes
            try:
                return super().convert_condition_field_eq_val_re(cond, state)
            finally:
                self.re_expression, self.re_escape_escape_char = saved

    assert SigmaRegularExpressionFlag.IGNORECASE in SecOpsBackend.re_flags      # |re|i -> (?i) prefix
    return Backend(processing_pipeline=secops_udm_pipeline())


def _unquoted_value(body: str) -> bool:
    """True if a comparison's right-hand side isn't a string, regex, number, list, variable or function
    (the backend sometimes writes Sigma wildcard values bare, e.g. `= +R +H *.cui`)."""
    masked = _strip_literals(body)
    return any(not re.match(r'\s*("|/|`|-?\d|%|\$|true\b|false\b|[a-z_]+\.[a-z_]+\()', masked[m.end():], re.I)
               for m in re.finditer(r"!=|(?<![<>!])=(?!=)", masked))


def _lower_ops(body: str) -> str:
    """AND / OR / NOT -> and / or / not, outside strings and regexes (YARA-L's documented spelling)."""
    masked, out, last = _strip_literals(body), [], 0
    for m in re.finditer(r"\b(AND|OR|NOT)\b", masked):
        out += [body[last:m.start()], m.group(1).lower()]
        last = m.end()
    return "".join(out + [body[last:]])


def _q(s) -> str:
    """A YARA-L meta string: one line, quotes and backslashes escaped."""
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _name(title: str) -> str:
    n = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:80].strip("_")
    return "sigma_" + (n or "rule")


def _techniques(tags) -> list[str]:
    out = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).lower())
        if m:
            out.append(m.group(1).upper())
    return sorted(set(out))


def convert(text: str, backend=None, source: str = "") -> tuple[dict | None, str]:
    """One Sigma rule (YAML text) -> ({name, yaral, techniques, ...}, '') or (None, why it was skipped)."""
    from sigma.collection import SigmaCollection
    try:
        col = SigmaCollection.from_yaml(text)
    except Exception as e:  # noqa: BLE001 - any parse problem means: skip this rule
        return None, f"not loadable: {type(e).__name__}"
    rules = [r for r in col.rules if type(r).__name__ == "SigmaRule"]
    if len(rules) != 1 or len(col.rules) != 1:
        return None, "correlation / multi-document rule (not supported)"
    r = rules[0]
    try:
        out = (backend or _backend()).convert(col, "yara_l")
    except Exception as e:  # noqa: BLE001
        msg = str(e).split("\n")[0]
        m = re.search(r"Field (\S+) is not a valid UDM field", msg)
        return None, f"field {m.group(1)} has no UDM mapping" if m else f"{type(e).__name__}: {msg[:120]}"
    q = out[0] if isinstance(out, list) and out else str(out)
    m = re.search(r"\n\s*events:\s*\n(.*?)\n\s*conditions?:\s*\n", q, re.S)
    if not m:
        return None, "converter output has no events section"
    body = m.group(1)
    if re.search(r"\$event\d+\.None\b", body):
        return None, "keyword search without a field (not expressible as a UDM filter)"
    if _unquoted_value(body):
        return None, "converter wrote a value it couldn't quote"
    body, why = _fix_mapping(body, r.logsource.category or "")
    if why:
        return None, why
    if re.search(r"\.port\s*!?=\s*/", body):
        return None, "regex on a numeric port field"
    alias = re.search(r"\$event\d+\.(?!(?:metadata|principal|target|src|observer|intermediary|about|network|"
                      r"security_result|extensions|additional)\.)(\w+)", body)
    if alias:     # 'hash', 'file_path', 'hostname', 'user', 'ip': UDM *search* shortcuts, not fields a rule can use
        return None, f"field {alias.group(1)} is a UDM search alias, not a rule field"
    body = re.sub(r"(\.(?:product_event_type|registry_value_data)\s*!?=\s*)(\d+)\b", r'\1"\2"', body)   # string fields
    lines = [ln.strip() for ln in _lower_ops(body).splitlines() if ln.strip()]
    tids = _techniques(r.tags)
    status = str(getattr(r.status, "name", r.status) or "").lower()
    level = str(getattr(r.level, "name", r.level) or "").lower()
    ls = r.logsource
    meta = [
        ("author", f"{r.author or 'SigmaHQ'} (Sigma rule converted to YARA-L by yadda)"),
        ("description", r.description or r.title),
        ("severity", level.capitalize() or "Medium"),
        ("mitre_attack_technique", ", ".join(tids)),
        ("sigma_id", str(r.id or "")), ("sigma_title", r.title), ("sigma_status", status), ("sigma_level", level),
        ("sigma_logsource", ":".join(x for x in (ls.category, ls.product, ls.service) if x)),
        ("sigma_source", source), ("false_positives", "; ".join(map(str, r.falsepositives or []))),
        ("reference", (r.references or [""])[0]),
        ("license", "Detection Rule License 1.1 (SigmaHQ) - keep the author and sigma_id attribution"),
    ]
    name = _name(r.title)
    yaral = (f"rule {name} {{\n  meta:\n" + "".join(f"    {k} = {_q(v)}\n" for k, v in meta if v) +
             "\n  events:\n" + "".join(f"    {ln}\n" for ln in lines) + "\n  condition:\n    $event1\n}\n")
    return {"name": name, "yaral": yaral, "techniques": tids, "status": status, "level": level,
            "title": r.title, "id": str(r.id or ""), "products": {x for x in (ls.product, ls.service) if x},
            "scope": scope(yaral)}, ""


FILE_CATEGORIES = {"file_event", "file_change", "file_rename", "file_delete", "file_access", "create_stream_hash"}
INTEGRITY_RID = {"untrusted": 0, "low": 4096, "medium": 8192, "medium plus": 8448, "high": 12288, "system": 16384}


def _fix_mapping(body: str, category: str) -> tuple[str, str]:
    """Field-mapping corrections for the backend (1.0.0), per Sigma logsource category:
    - file_event is a file *creation* (Sysmon 11), not FILE_UNCATEGORIZED;
    - in file and module-load events the process doing it is principal.process (Image), the file is target.file;
      TargetFilename is a full path (target.file.full_path), not the repeated target.file.names;
    - IntegrityLevel is a number in UDM (integrity_level_rid), not the word Sysmon writes."""
    if category == "file_event":
        body = body.replace('"FILE_UNCATEGORIZED"', '"FILE_CREATION"')
    if category in FILE_CATEGORIES | {"image_load", "driver_load"}:
        body = body.replace("$event1.target.process.", "$event1.principal.process.")
    if category in FILE_CATEGORIES:
        body = body.replace("$event1.target.file.names", "$event1.target.file.full_path")

    def rid(m):
        n = INTEGRITY_RID.get(m.group(3).lower())
        if n is None:
            raise KeyError(m.group(3))
        return f"{m.group(1)} {m.group(2)} {n}"
    try:
        body = re.sub(r'(\S*integrity_level_rid)\s*(!=|=)\s*"([^"]*)"(?:\s*nocase)?', rid, body)
    except KeyError as e:
        return body, f"integrity level {e.args[0]!r} has no number in UDM"
    return body, ""


def _platforms(products: set) -> set:
    return set().union(*(PRODUCT_PLATFORMS.get(p.lower(), set()) for p in products)) if products else set()


def cmd_sigma(args):
    """yadda sigma <environment> [--threats | T-ids] [--all-data] [--experimental] [--hunting] [--max N]"""
    from delib.facts import scope_states
    from delib.priorities import _threat_list
    from delib.telemetry import _read_inventory, present
    if not args or args[0].startswith("--"):
        die("usage: yadda sigma <environment> [--threats | T1234 ...] [--all-data] [--experimental] [--hunting] [--max 3]")
    c = envdir(args[0])
    flags = {a for a in args[1:] if a.startswith("--")}
    per_tech = 3
    if "--max" in flags:
        i = args.index("--max")
        if i + 1 >= len(args) or not args[i + 1].isdigit() or int(args[i + 1]) < 1:
            die("--max needs a number of 1 or more, e.g. --max 3")
        per_tech = int(args[i + 1])
        flags.discard("--max")
    max_val = args[args.index("--max") + 1] if "--max" in args else None
    words = [a for a in args[1:] if not a.startswith("--") and a != max_val]
    asked = [a.upper() for a in words if re.fullmatch(r"T\d{4}(\.\d{3})?", a, re.I)]
    if len(asked) != len(words):
        die(f"not a technique ID: {', '.join(a for a in words if a.upper() not in asked)} (e.g. T1059.001)")
    unknown = flags - {"--threats", "--all-data", "--experimental", "--hunting"}
    if unknown:
        die(f"unknown option {sorted(unknown)[0]}")
    if not (SIGMA_REPO / "rules").is_dir():
        die("SigmaHQ rules aren't installed - run: yadda setup")

    rows, in_scope, plats = scope_states(c)
    state = {r["id"]: r["state"] for r in rows}
    covered = {t for t, s in state.items() if s in ("validated", "detected", "limited")}
    threats = _threat_list(c)
    used_by = Counter(t for _, _, ts in threats for t in ts)
    if asked:
        from delib.attack import tech_index
        unknown_t = [t for t in asked if t not in tech_index()["techs"]]
        if unknown_t:
            die(f"not in ATT&CK {', '.join(unknown_t)}")
        targets, why = set(asked), "named technique"
    elif "--threats" in flags:
        if not threats:
            die(f"no THREATS= in {c / 'environment.env'} - set it with yadda actors ... --environment {c.name} --set")
        targets, why = {t for t in used_by if t in in_scope} - covered, "threat gap"
    else:
        targets, why = set(in_scope) - covered, "gap"
    if not targets:
        print(f"{c.name}: nothing to look for - every target technique already has a working rule")
        return
    inv_f = inputs.current(c, "inventory")
    have = present(_read_inventory(inv_f)) if inv_f else None
    check_data = have is not None and "--all-data" not in flags

    dirs = RULE_DIRS + (("rules-threat-hunting",) if "--hunting" in flags else ())
    files = sorted(f for d in dirs for f in (SIGMA_REPO / d).rglob("*.yml"))
    ok_status = STATUS_OK | ({"experimental"} if "--experimental" in flags else set())
    backend, skipped, picked = _backend(), Counter(), defaultdict(list)
    tag_re = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.I)
    for f in files:
        text = read_text(f)
        tags = {t.upper() for t in tag_re.findall(text)}
        # exact technique, or a sub-technique rule for a parent target (a parent-tagged rule isn't sub coverage)
        hit = {t for t in targets if t in tags or any(x.startswith(t + ".") for x in tags)}
        if not hit:
            continue
        st = re.search(r"^status:\s*(\w+)", text, re.M)
        if st and st.group(1).lower() not in ok_status:
            skipped[f"status {st.group(1).lower()}"] += 1
            continue
        res, reason = convert(text, backend, f.relative_to(SIGMA_REPO).as_posix())
        if res is None:
            skipped[reason if reason.startswith(("field", "keyword", "correlation")) else "other conversion error"] += 1
            continue
        rp = _platforms(res["products"])
        if plats and rp and not rp & plats:
            skipped["not on the environment's platforms"] += 1
            continue
        ets, lts = res["scope"]["event_types"], res["scope"]["log_types"]
        if have is None or not ets:
            data = "unknown"
        else:
            data = "yes" if ets & have["event_types"] and (not lts or lts & have["log_types"]) else "no"
        if check_data and data == "no":
            skipped["environment doesn't send the events it needs"] += 1
            continue
        res.update(data=data, file=f.relative_to(SIGMA_REPO).as_posix())
        for t in hit:
            picked[t].append(res)

    # Best few per technique: data known present first, then stable before test, then severity.
    order = lambda r: (r["data"] != "yes", r["status"] != "stable", LEVEL_RANK.get(r["level"], 5), r["name"])
    chosen, seen_names = {}, {}
    for t in sorted(picked, key=lambda t: (-used_by.get(t, 0), t)):
        for r in sorted(picked[t], key=order)[:per_tech]:
            if r["id"] in chosen:
                chosen[r["id"]]["targets"].add(t)
                continue
            name = r["name"]
            if name in seen_names and seen_names[name] != r["id"]:          # two Sigma rules with one title
                name = f"{name}_{r['id'][:8]}"
                r = {**r, "name": name, "yaral": r["yaral"].replace(f"rule {r['name']} {{", f"rule {name} {{", 1)}
            seen_names[name] = r["id"]
            chosen[r["id"]] = {**r, "targets": {t}}

    out = out_dir(c) / "4_sigma_candidates"
    if out.exists():
        _rmtree(out)                                      # regenerated each run (earlier days' folders keep theirs)
    out.mkdir()
    from delib.upstream import installed_sha
    pin = installed_sha(SIGMA_REPO) or read_lock().get("sigma", "")
    table = []
    for r in sorted(chosen.values(), key=lambda r: r["name"]):
        write_text(out / f"{r['name']}.yaral", r["yaral"])
        ts = sorted(r["targets"])
        table.append({"rule": r["name"], "covers": " ".join(ts), "reason": why,
                      "threat_groups": max((used_by.get(t, 0) for t in ts), default=0),
                      "current_state": ", ".join(sorted({state.get(t, "not in scope") for t in ts})),
                      "data_present": r["data"], "event_types": " ".join(sorted(r["scope"]["event_types"])),
                      "sigma_status": r["status"], "sigma_level": r["level"], "sigma_title": r["title"],
                      "sigma_file": r["file"], "sigma_commit": pin[:12]})
    write_csv(out / "candidates.csv", list(table[0]) if table else ["rule"], table)
    gained = {t for row in table for t in row["covers"].split()}
    print(f"{c.name}: {len(chosen)} candidate rules for {len(gained)} of {len(targets)} target techniques ({why}s) "
          f"-> {out}")
    print("  Not counted as coverage: deploy the ones you want in SecOps; the next yadda run (or yadda import) counts them.")
    if have is None:
        print("  No telemetry inventory in inputs/ yet, so data_present is 'unknown': run yadda data first to keep only rules whose events arrive.")
    if skipped:
        print("  skipped: " + ", ".join(f"{n} {k}" for k, n in skipped.most_common(6)))
    missing = sorted(targets - gained, key=lambda t: (-used_by.get(t, 0), t))
    if missing:
        print(f"  no usable Sigma rule for {len(missing)} techniques, e.g. {', '.join(missing[:10])}")


def candidates(c: Path) -> list[dict]:
    """The newest candidates.csv rows for this environment (for the dashboard and workbook), or []."""
    found = sorted((HOME / "output" / c.name).glob("*/4_sigma_candidates/candidates.csv"))
    return read_csv(found[-1])[1] if found else []
