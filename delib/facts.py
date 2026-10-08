"""facts - what yadda knows about one environment: techniques.yaml scores, enabled rules and their evidence exports
(rule health, FP, log types), and the state of every in-scope technique."""
from __future__ import annotations

from delib.cache import per_environment
from delib import inputs

import datetime as dt
import re
from collections import Counter, defaultdict
from pathlib import Path
from delib.config import die, read_csv, read_env, read_text, TECH_RE, yaml_rt
from delib.attack import _scope, attack, tech_index
from delib.yaral import scope
from delib.routes import best_route, inventory_file, observed, routes
from delib.telemetry import _count, _dc_sources, _mapping, _read_export, _when, day_first


def _day(d):
    """Any logbook date (date, naive or aware datetime, ISO string) -> naive midnight datetime (aware ones
    converted to UTC first), as DeTT&CT's files use. One type everywhere keeps dates comparable."""
    if d is None or d == "":
        return None
    if isinstance(d, str):
        try:
            d = dt.datetime.fromisoformat(d.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(d, dt.datetime):
        if d.tzinfo is not None:
            d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return d.replace(hour=0, minute=0, second=0, microsecond=0)
    if isinstance(d, dt.date):
        return dt.datetime(d.year, d.month, d.day)
    return None


def latest(logbook) -> tuple:
    """(score, date, comment) of the newest entry by day; on the same day the later entry in the list wins"""
    entries = list(logbook or [])
    dated = [(i, e) for i, e in enumerate(entries) if _day(e.get("date"))]
    if dated:
        e = max(dated, key=lambda ie: (_day(ie[1]["date"]), ie[0]))[1]
    else:
        e = entries[0] if entries else {}
    return e.get("score", -1), e.get("date"), e.get("comment", "")


def normalise_logbooks(data) -> None:
    """Give every score_logbook date in a loaded techniques.yaml the same type (naive midnight datetime); mixed
    types can't be compared."""
    for t in (data or {}).get("techniques") or []:
        for kind in ("detection", "visibility"):
            for obj in t.get(kind) or []:
                book = obj.get("score_logbook")
                if not isinstance(book, list):
                    continue
                for e in book:
                    if e.get("date"):
                        e["date"] = _day(e["date"]) or e["date"]
                # DeTT&CT's template entry has no date and can't be compared with dated entries, so drop it.
                if any(e.get("date") for e in book) and any(not e.get("date") for e in book):
                    book[:] = [e for e in book if e.get("date")]


_loaded: dict = {}


def read_yaml_fast(f: Path):
    """Read-only YAML load with PyYAML's C loader (much faster than the round-trip loader), cached per file version.
    Files that are written back use yaml_rt() so comments survive."""
    import yaml
    key = (str(f), f.stat().st_mtime_ns, f.stat().st_size)
    if key not in _loaded:
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        _loaded[key] = yaml.load(read_text(f), Loader=loader)
    return _loaded[key]


def load_techniques(c: Path) -> dict:
    f = c / "techniques.yaml"
    if not f.exists():
        return {}
    data = read_yaml_fast(f) or {}
    out = {}
    for t in data.get("techniques") or []:
        det = next((d for d in t.get("detection", []) if d.get("applicable_to") == ["all"]), None)
        score, date, comment = latest(det["score_logbook"]) if det else (-1, None, "")
        out[t["technique_id"]] = {
            "name": t.get("technique_name", ""),
            "score": score, "date": date, "comment": comment,
            "rules": [l for l in (det or {}).get("location", []) if l],
            "visibility": max([latest(v["score_logbook"])[0] for v in t.get("visibility", [])] or [0]),
        }
    return out


def _enabled_rules(c: Path) -> tuple[dict, list]:
    """Enabled, non-archived rules from the last pull: ({name: {id, techniques}}, [untagged names])."""
    f = c / "rule_config.yaml"
    if not f.exists():
        die(f"no rules pulled for {c.name} - run: yadda pull {c.name}")
    cfg = yaml_rt().load(f.open(encoding="utf-8")) or {}
    a = attack()
    RETAGS.clear()
    DROPPED.clear()
    tagged, untagged = {}, []
    for name, state in cfg.items():
        if not state.get("enabled") or state.get("archived"):
            continue
        rf = c / "rules" / f"{name}.yaral"
        text = rf.read_text(encoding="utf-8") if rf.exists() else ""
        meta = re.search(r"meta:(.*?)\n\s*(events|match|outcome|condition):", text, re.S)
        techs = set()
        for t in set(TECH_RE.findall(meta.group(1) if meta else "")):
            if t in a["names"]:
                techs.add(t)
            elif t in a["replaced"]:
                techs.add(a["replaced"][t])
                RETAGS[(t, a["replaced"][t])].append(name)
            else:
                DROPPED[(t, "deprecated by MITRE" if t in a["deprecated"] else "not an ATT&CK ID")].append(name)
        if techs:
            tagged[name] = {"id": str(state.get("id") or ""), "techniques": sorted(techs)}
        else:
            untagged.append(name)
    return tagged, untagged


RETAGS: dict = defaultdict(list)    # (old id, new id) -> rules, filled by _enabled_rules


DROPPED: dict = defaultdict(list)   # (id, reason) -> rules


def _report_tag_problems() -> None:
    """Tell the user which rule tags use IDs MITRE has replaced or removed, so the rules can be updated."""
    if RETAGS:
        n = len({r for v in RETAGS.values() for r in v})
        print(f"  {n} rules use technique IDs MITRE has REPLACED - counted under the new ID; update the rule meta when convenient:")
        for (old, new), rules in sorted(RETAGS.items()):
            print(f"   - {old} -> {new} {attack()['names'].get(new, '')} ({len(set(rules))} rules, e.g. {sorted(set(rules))[0]})")
    if DROPPED:
        print("  technique tags NOT counted:")
        for (tid, why), rules in sorted(DROPPED.items()):
            print(f"   - {tid}: {why} ({len(set(rules))} rules, e.g. {sorted(set(rules))[0]})")


def _set_score(data, tid: str, score: int, comment: str):
    """Add a dated detection score for a technique in loaded techniques.yaml data; returns the technique."""
    tech = next((t for t in data["techniques"] if t["technique_id"] == tid), None)
    if tech is None:
        name = attack()["names"].get(tid) or die(f"{tid} is not an ATT&CK technique")
        tech = {"technique_id": tid, "technique_name": name,
                "detection": [{"applicable_to": ["all"], "location": [""], "comment": "", "score_logbook": []}],
                "visibility": [{"applicable_to": ["all"], "comment": "",
                                "score_logbook": [{"date": None, "score": 0, "comment": "", "auto_generated": True}]}]}
        data["techniques"].append(tech)
    det = next((d for d in tech["detection"] if d.get("applicable_to") == ["all"]), None)
    if det is None:
        det = {"applicable_to": ["all"], "location": [""], "comment": "", "score_logbook": []}
        tech["detection"].append(det)
    det["score_logbook"] = [e for e in det.get("score_logbook") or [] if e.get("date")]
    normalise_logbooks(data)
    today = _day(dt.datetime.now(dt.timezone.utc))
    # One entry per day, like Dettectinator: any entries already dated today are replaced.
    det["score_logbook"] = [e for e in det["score_logbook"] if _day(e.get("date")) != today]
    det["score_logbook"].append({"date": today, "score": score, "comment": comment})
    return tech


AUTO = "Auto added by yadda."      # comment prefix of scores yadda sets itself (evidence may change them later)
NEW_TECHNIQUES_FILE = {"version": 1.2, "file_type": "technique-administration", "name": "", "domain": "enterprise-attack",
                       "platform": ["all"], "techniques": []}


def sync_detections(data: dict, rules: dict, prefix: str = "SecOps") -> list[str]:
    """Put the enabled rules into techniques.yaml data (DeTT&CT's technique-administration format, so the file still
    opens in DeTT&CT): rules = {rule name: [techniques]}. A technique a rule newly covers gets score 1; a rule that
    is gone is removed from its techniques' locations and a technique left with no rule drops to -1. Every change is
    a dated score_logbook entry, one per day (the same convention as Dettectinator). Returns the changes."""
    today = _day(dt.datetime.now(dt.timezone.utc))
    names = attack()["names"]
    techs = {t["technique_id"]: t for t in data.setdefault("techniques", []) or []}
    if data["techniques"] is None:
        data["techniques"] = []
    wanted = defaultdict(list)
    for rule, ts in rules.items():
        for t in ts:
            wanted[t].append(f"{prefix}: {rule}")
    changes = []

    def log(det, text, score=None):
        # today's entry, if any: the last one, which is the one latest() reads
        e = next((e for e in reversed(det["score_logbook"]) if _day(e.get("date")) == today), None)
        if e is not None:
            e["comment"] = f"{e.get('comment') or ''}. {text}".lstrip(". ")
            if score is not None:
                e["score"] = score
        else:
            det["score_logbook"].append({"date": today, "score": latest(det["score_logbook"])[0] if score is None else score,
                                         "comment": f"{AUTO} {text}"})

    for tid, locs in sorted(wanted.items()):
        tech = techs.get(tid)
        if tech is None:
            tech = {"technique_id": tid, "technique_name": names.get(tid, ""), "detection": [], "visibility": [
                {"applicable_to": ["all"], "comment": "", "score_logbook": [{"date": None, "score": 0, "comment": "",
                                                                              "auto_generated": True}]}]}
            data["techniques"].append(tech)
            techs[tid] = tech
        if isinstance(tech.get("detection"), dict):
            tech["detection"] = [tech["detection"]]
        det = next((d for d in tech.setdefault("detection", []) if d.get("applicable_to") == ["all"]), None)
        if det is None:
            det = {"applicable_to": ["all"], "location": sorted(locs), "comment": "",
                   "score_logbook": [{"date": today, "score": 1, "comment": f"{AUTO} Detection rule added: {', '.join(sorted(locs))}"}]}
            tech["detection"].append(det)
            changes.append(f"{tid}: new")
            continue
        det.setdefault("location", [])
        det.setdefault("score_logbook", [])
        have = {str(x).lower(): x for x in det["location"]}
        for loc in sorted(locs):
            if loc.lower() not in have:
                det["location"] = [x for x in det["location"] if x] + [loc]    # drop DeTT&CT's empty template entry
                # a rule now covers it: at least 1 (unverified), never lower than what it was
                log(det, f"Detection rule added: {loc}", max(latest(det["score_logbook"])[0], 1))
                changes.append(f"{tid}: + {loc}")
            elif have[loc.lower()] != loc:                 # only the case changed
                det["location"][det["location"].index(have[loc.lower()])] = loc
    for tid, tech in techs.items():
        for det in tech.get("detection") or []:
            if det.get("applicable_to") != ["all"]:
                continue
            for loc in list(det.get("location") or []):
                if str(loc).startswith(f"{prefix}: ") and loc not in wanted.get(tid, []):
                    det["location"].remove(loc)
                    log(det, f"Detection rule removed: {loc}", -1 if not [x for x in det["location"] if x] else None)
                    changes.append(f"{tid}: - {loc}")
    for tech in data["techniques"]:
        for det in tech.get("detection") or []:
            det["location"] = sorted(det.get("location") or [], key=str)
    return changes


def _summary(c: Path) -> dict:
    """The status / history.csv line: the dashboard's states, for techniques on the environment's platforms."""
    rows = scope_states(c)[0]
    st = Counter(r["state"] for r in rows)
    dates = [str(r["date"]) for r in load_techniques(c).values() if r["date"]]
    return {"date": str(dt.date.today()), "environment": c.name,
            "enabled_rules": len(_enabled_rules(c)[0]) if (c / "rule_config.yaml").exists() else 0,
            "detected_ge3": st["detected"] + st["validated"],
            "validated_ge4": st["validated"],
            "limited_2": st["limited"],
            "unverified_1": st["unverified"],
            "data_no_rule": st["buildable"],
            "thin_data": st["thin"],
            "blind": st["blind"],
            "platform_not_seen": st["unseen"],
            "in_scope": len(rows),
            "last_change": max(dates)[:10] if dates else ""}


# ---------------------------------------------------------------- rule evidence exports (one reader for every view)
def base_name(name: str) -> str:
    """Display name behind yadda's own suffixes: '__ru_<id>' (Content Manager duplicates) and '__dupN' (yadda import)."""
    return name.split("__ru_")[0].split("__dup")[0].lower()


def read_health(path: Path, rules: dict) -> dict:
    """rule_health export -> {rule: {'last': date|None, 'count': int, 'raw': str}} for the given {rule: id}.
    A row is matched by rule id first. Only rules whose id isn't in the export fall back to the display name, so
    two rules sharing a display name keep their own rows when the export has ids."""
    tail = lambda i: str(i or "").rsplit("/", 1)[-1]
    rows = _read_export(path, {"rule_id": ("rule_id", "name", "id"), "name": ("display_name", "rule_name"),
                               "last": ("detection_time", "last_fired", "latest_detection_time"),
                               "count": ("detection_count", "detections", "total_detection_count")})
    export_ids = {tail(r["rule_id"]) for r in rows if r["rule_id"]}
    by_id = {tail(i): n for n, i in rules.items() if i}
    by_name = defaultdict(list)
    for n, i in rules.items():
        if not i or tail(i) not in export_ids:
            by_name[base_name(n)].append(n)
    dayfirst = day_first(r["last"] for r in rows)
    out = {}
    for r in rows:
        hit = by_id.get(tail(r["rule_id"]))
        for n in ([hit] if hit else by_name.get(base_name(r["name"]), [])):
            row = {"last": _when(r["last"], dayfirst), "count": _count(r["count"]), "raw": r["last"]}
            if n in out:                     # several rows for one rule (versions): latest date, summed count
                prev = out[n]
                row = {"last": max(filter(None, (prev["last"], row["last"])), default=None),
                       "count": prev["count"] + row["count"], "raw": prev["raw"] or row["raw"]}
            out[n] = row
    return out


def read_fp(path: Path) -> dict:
    """rule_fp export -> {base display name: (cases, malicious, not_malicious)}. Reads the per-reason export
    (rule_name, reason, case_count - distinct cases) and the summary one (case_count, malicious, not_malicious)."""
    head = [h.strip().lstrip("$").lower() for h in read_csv(path)[0] if h]
    out = defaultdict(lambda: [0, 0, 0])
    if "reason" in head:
        for r in _read_export(path, {"name": ("rule_name", "display_name"), "reason": ("reason",),
                                     "cases": ("case_count", "cases")}):
            n, k = _count(r["cases"]), base_name(r["name"])
            out[k][0] += n
            if r["reason"].upper() == "MALICIOUS":
                out[k][1] += n
            elif r["reason"].upper() == "NOT_MALICIOUS":
                out[k][2] += n
    else:
        for r in _read_export(path, {"name": ("rule_name", "display_name"), "cases": ("case_count", "cases"),
                                     "bad": ("malicious",), "good": ("not_malicious",)}):
            out[base_name(r["name"])] = [_count(r["cases"]), _count(r["bad"]), _count(r["good"])]
    return {k: tuple(v) for k, v in out.items()}


def fp_pct(malicious: int, not_malicious: int):
    """Share of cases closed NOT_MALICIOUS among cases closed with a verdict (other reasons don't dilute it)."""
    decided = malicious + not_malicious
    return round(100 * not_malicious / decided) if decided else None


def thresholds(c: Path) -> dict:
    """Evidence thresholds for this environment (environment.env, set by yadda evidence options): every view uses these."""
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    get = lambda k, d: int(env[k]) if str(env.get(k, "")).isdigit() else d
    return {"days": get("EVIDENCE_DAYS", 90), "fp_max": get("FP_MAX", 50), "min_cases": get("MIN_CASES", 5)}


# ---------------------------------------------------------------- per-rule facts (dashboard + review)
@per_environment(key=lambda days=None: days)
def _rule_facts(c: Path, days: int | None = None) -> dict:
    tagged, untagged = _enabled_rules(c) if (c / "rule_config.yaml").exists() else ({}, [])
    retags, dropped = dict(RETAGS), dict(DROPPED)
    cfg = (yaml_rt().load((c / "rule_config.yaml").open(encoding="utf-8")) or {}) if (c / "rule_config.yaml").exists() else {}
    th = thresholds(c)
    days = days or th["days"]
    observed = defaultdict(dict)
    names = list(tagged) + untagged
    ids = {n: str((cfg.get(n) or {}).get("id") or "") for n in names}
    health_f, fp_f, lt_f = (inputs.current(c, k) for k in ("rule_health", "rule_fp", "rule_logtypes"))
    health = read_health(health_f, ids) if health_f else {}
    fp = read_fp(fp_f) if fp_f else {}
    by_name = defaultdict(list)
    for n in names:
        by_name[base_name(n)].append(n)
    if lt_f:
        for r in _read_export(lt_f, {"name": ("rule_name", "display_name"), "lt": ("log_type",),
                                                       "n": ("detection_count", "count", "detections")}):
            for rule in by_name.get(base_name(r["name"]), []):
                if r["lt"]:
                    observed[rule][r["lt"]] = observed[rule].get(r["lt"], 0) + _count(r["n"])
    today = dt.date.today()
    rules = []
    for name in sorted(names):
        f = c / "rules" / f"{name}.yaral"
        text = read_text(f) if f.exists() else ""
        sc = scope(text) if f.exists() else {"event_types": set(), "log_types": set(), "product_event_types": set()}
        # products a rule names without a log type (metadata.vendor_name / product_name, or Google's meta data_source):
        # used only to tell which ATT&CK platform the rule works on
        products = {m.group(2) for m in re.finditer(r'metadata\.(vendor_name|product_name)\s*=\s*"([^"]+)"', text)}
        products |= {m.group(1) for m in re.finditer(r'^\s*data_source\s*=\s*"([^"]+)"', text, re.M)}
        h = health.get(name)
        # The FP and log-type exports only carry display names: rules sharing one can't be told apart there,
        # so their FP numbers aren't used (rule health is matched by rule id and is unaffected).
        shared = len(by_name[base_name(name)])
        cases, mal, notmal = fp.get(base_name(name), (0, 0, 0)) if shared == 1 else (0, 0, 0)
        pct = fp_pct(mal, notmal)
        if not health_f:
            state = "no export"
        elif h is None:
            state = "not in export"
        elif h["last"] is None and h["count"]:
            state = "fired, date unknown"    # detections exist but the export has no time: not "never fired"
        elif h["last"] is None:
            state = "never fired"
        elif (today - h["last"]).days > days:
            state = "stale"
        else:
            state = "firing"
        rules.append({"name": name, "techniques": tagged.get(name, {}).get("techniques", []), "state": state,
                      "last": h["last"] if h else None, "count": h["count"] if h else None,
                      "cases": cases, "malicious": mal, "fp_pct": pct,
                      "noisy": pct is not None and (mal + notmal) >= th["min_cases"] and pct > th["fp_max"],
                      "logtypes": sc["log_types"], "eventtypes": sc["event_types"], "products": products, "product_event_types": sc["product_event_types"],
                      "observed": observed.get(name, {}), "imported": bool((cfg.get(name) or {}).get("imported")),
                      "duplicate": "__ru_" in name or "__dup" in name, "shared_name": shared,
                      "retagged": [o for (o, n), rr in retags.items() if name in rr]})
    return {"rules": rules, "untagged": untagged, "retags": retags, "dropped": dropped, "has_health": bool(health)}


STATES = [  # key, label, colour, owner/meaning
    ("validated", "Validated (4-5)", "#0a7d0a", "proven by a test"),
    ("detected", "Detected (3)", "#0ca30c", "rule fired recently, not noisy (not proof it catches every variant)"),
    ("limited", "Limited (2)", "#fab219", "fires, but noisy or narrow"),
    ("unverified", "Unverified (1)", "#a3a29b", "rule deployed, no evidence yet"),
    ("hand", "Scored by hand, no rule", "#8fc99a", "a score typed by hand (e.g. proven on an EDR) with no enabled SIEM rule: shown, never counted"),
    ("buildable", "Data, no rule", "#2a78d6", "every input of a MITRE detection route is seen: you could write a rule today"),
    ("thin", "Some data", "#ec835a", "some inputs of a MITRE detection route are seen, not all"),
    ("blind", "No data seen", "#d03b3b", "the platform's logs are in the SIEM, but none of the route's inputs"),
    ("unseen", "Platform not seen", "#9b7fc4", "no log type of the route's platform is in the SIEM (not proof the environment doesn't use it)"),
    ("unknown", "Can't tell", "#d6d5cf", "no telemetry inventory yet, no MITRE route on these platforms, or inputs that can't be measured"),
]

# Threat context (software, procedures, Attack Flow) judges a technique on the platform the tool or step runs on:
# a rule on SaaS audit logs doesn't see the same technique carried out on a Windows host.
ELSEWHERE = ("elsewhere", "Detected, not on this platform", "#c4e3bd",
             "a rule detects the technique, but only on another platform (e.g. SaaS) than the one this tool or step runs on")
CONTEXT_STATES = STATES[:2] + [ELSEWHERE] + STATES[2:]


@per_environment()
def scope_states(c: Path):
    """(rows, in_scope, scope_platforms) for every technique on the environment's platforms."""
    sp = _scope(c)
    ins = {tid: t for tid, t in tech_index()["techs"].items() if t["platforms"] & sp}
    return _states(c, ins, sp)[0], ins, sp


@per_environment(key=lambda in_scope, scope_plats: (frozenset(in_scope), frozenset(scope_plats)))
def _states(c: Path, in_scope: dict, scope_plats: set):
    """State of every in-scope technique for this environment (one of STATES), plus the inputs it was built from."""
    have = load_techniques(c)
    present_dc = set()            # unused (telemetry is judged by MITRE routes, see routes.py); kept in the return value
    mapping = _mapping()
    measurable = set(_dc_sources(mapping))
    obs = observed(inventory_file(c))
    from delib.routes import log_type_platforms, rule_platforms
    table = log_type_platforms()
    ruled, det_on = set(), defaultdict(set)
    for r in _rule_facts(c)["rules"]:
        ruled |= set(r["techniques"])
        if r["state"] == "firing" and not r["noisy"]:
            ps = rule_platforms(r, table, obs["et_platforms"])
            for t in r["techniques"]:
                det_on[t] |= {ANY} if ps is None else ps
    rows = []
    for tid, t in in_scope.items():
        h = have.get(tid, {})
        s = h.get("score", -1)
        rs = routes(t, scope_plats, obs, measurable)
        best = best_route(rs)
        level = best["level"] if best else "unknown"
        vis = {"all": 2, "some": 1}.get(level, 0)
        need = {i["dc"] for i in best["inputs"] if i["measurable"]} if best else set()
        got = {i["dc"] for i in best["inputs"] if i["seen"]} if best else set()
        if tid in ruled and s < 1:
            s = 1                           # an enabled rule covers it: at least unverified, whatever the file says
        state = ("hand" if s >= 1 and tid not in ruled
                 else "validated" if s >= 4 else "detected" if s == 3 else "limited" if s == 2 else "unverified" if s == 1
                 else "buildable" if level == "all" else "thin" if level == "some"
                 else "blind" if level == "none" else "unseen" if level == "unseen" else "unknown")
        rows.append({"id": tid, "name": t["name"], "tactics": t["tactics"], "state": state, "score": s, "vis": vis,
                     "need": need, "got": got, "routes": rs, "route": best, "prev": t["prevalence"],
                     # a route with every input but one: a rule can usually be written now (it may miss variants)
                     "one_short": bool(best and best["level"] == "some" and best["needed"] - best["seen"] == 1),
                     "missing": sorted(need - got),
                     # platforms the firing, non-noisy rules for it work on ('*' = a rule that names no log type)
                     "detected_on": det_on.get(tid, set()),
                     "rules": h.get("rules", []), "comment": h.get("comment", "")})
    return rows, have, present_dc, mapping, measurable


ANY = "*"


def detected_on(row: dict, platforms: set) -> bool:
    """Detected (validated/detected state) by a rule that works on one of `platforms`. A rule naming no log type
    counts everywhere; a technique scored 4-5 by a test counts everywhere (the test proved it)."""
    if row["state"] not in ("validated", "detected"):
        return False
    on = row.get("detected_on") or set()
    return row["state"] == "validated" or ANY in on or not on or bool(on & platforms)
