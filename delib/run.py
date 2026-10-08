"""run - `yadda run <environment>`: every step and every output in one go, into output/<environment>/<date>/.

Skip steps with -<step> (e.g. `yadda run acme -sigma -robustness`). A step that fails is reported and the rest still
run. Everything a step prints goes to run_log.txt in the output folder; the terminal shows one line per step and
the headline.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import shutil
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from delib import inputs
from delib.config import HOME, _rmtree, envdir, die, out_dir, read_csv, read_env, write_rows, write_text

STEPS = [  # name, what it does
    ("pull", "pull the deployed rules from SecOps (environment.env), else re-read the imported rules"),
    ("queries", "run the SecOps queries through the API into inputs/"),
    ("data", "check the telemetry inventory; list what can't be mapped"),
    ("evidence", "rule health / false positives / log types -> detection scores"),
    ("robustness", "MITRE Detection Coverage Calculator on the enabled rules"),
    ("review", "rules that need a person to look at them -> rule_review.csv"),
    ("atomics", "Atomic Red Team tests for techniques with rules -> validation.csv"),
    ("sigma", "SigmaHQ rules converted to YARA-L for the gaps (candidates, not counted)"),
]


def has_api(c: Path) -> bool:
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    inst = env.get("GOOGLE_SECOPS_INSTANCE", "")
    return bool(inst) and "INSTANCE_ID" not in inst and bool(env.get("GOOGLE_SECOPS_API_BASE_URL"))


@contextlib.contextmanager
def _to_log(log: Path):
    """Send everything printed, by yadda and by subprocesses, to the run log.
    Redirects both the file descriptors (inherited by subprocesses) and sys.stdout / sys.stderr: on Windows,
    sys.stdout writes to the console handle, which fails with 'The handle is invalid' once descriptor 1 is redirected."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.flush()
        except (OSError, ValueError):
            pass
    saved = os.dup(1), os.dup(2)
    py_out, py_err = sys.stdout, sys.stderr
    with open(log, "a", encoding="utf-8", errors="replace", buffering=1) as f:
        os.dup2(f.fileno(), 1)
        os.dup2(f.fileno(), 2)
        sys.stdout = sys.stderr = f
        try:
            yield
        finally:
            sys.stdout, sys.stderr = py_out, py_err
            try:
                f.flush()
            except (OSError, ValueError):
                pass
            os.dup2(saved[0], 1)            # always give the terminal back, whatever happened above
            os.dup2(saved[1], 2)
            os.close(saved[0])
            os.close(saved[1])


def _step(name: str, fn, log: Path, results: list, who: str = "") -> None:
    t0 = time.time()
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"\n===== {name} =====\n")
    err = None
    start = log.stat().st_size
    try:
        with _to_log(log):
            note = fn()
    except SystemExit as e:
        err, note = str(e.code), None
    except Exception as e:  # noqa: BLE001 - one step's bug must not cost the other outputs
        err, note = f"{type(e).__name__}: {e}", None
    secs = time.time() - t0
    if err:
        err = err.strip().splitlines()[0][:200]
    elif not note:                                  # the step's own last line is its summary
        with open(log, encoding="utf-8", errors="replace") as f:
            f.seek(start)
            said = [ln.strip() for ln in f.read().splitlines() if ln.strip() and not ln.startswith("=====")]
        mine = [ln for ln in said if who and ln.startswith(who + ":")]     # "<environment>: ..." is a step's summary
        note = (mine[0] if mine else said[-1] if said else "")[:160]
    results.append((name, "FAILED" if err else "ok", err or note or ""))
    print(f"  {'FAILED' if err else 'ok':6} {name:11} {secs:5.0f}s  {err or note or ''}"[:160], flush=True)


def cmd_run(args):
    """yadda run <environment> [-step ...]  - everything: rules, exports, scores, review, Sigma, all outputs."""
    from delib.analysis import cmd_review
    from delib.commands import cmd_data, cmd_evidence, cmd_pull, cmd_sync
    from delib.robustness import cmd_robustness
    from delib.secops_api import run_queries
    from delib.sigma import cmd_sigma
    from delib.upstream import DCC_REPO
    from delib.validation import cmd_atomics
    names = [n for n, _ in STEPS]
    if not args or args[0].startswith("-"):
        die("usage: yadda run <environment> [--ask] [" + " ".join(f"-{n}" for n in names) + "]")
    c = envdir(args[0])
    ask = "--ask" in args
    skip = {a.lstrip("-") for a in args[1:] if a != "--ask"} - {"layers"}   # -layers is ignored: layers are always written
    unknown = skip - set(names)
    if unknown:
        die(f"unknown step {sorted(unknown)[0]}: steps are {', '.join(names)}")
    out = out_dir(c)
    log = out / "run_log.txt"
    with open(log, "a", encoding="utf-8") as f:        # appended: an earlier run today keeps its details
        f.write(f"\n########## yadda run {' '.join(args)}  {dt.datetime.now():%Y-%m-%d %H:%M}\n")
    api = has_api(c)
    print(f"{c.name}: running into {out}")
    results = []
    plan = {
        "pull": (lambda: cmd_pull([c.name]) or "rules pulled from SecOps") if api else
                (lambda: cmd_sync([c.name]) or "no SecOps API in environment.env: re-read the rules in rules/"),
        "queries": (lambda: f"exports saved to inputs/: {', '.join(run_queries(c)) or 'none'}") if api else None,
        "data": lambda: cmd_data([c.name]),
        "evidence": lambda: cmd_evidence([c.name]),
        "robustness": (lambda: cmd_robustness([c.name])) if DCC_REPO.exists() else None,
        "review": lambda: cmd_review([c.name]),
        "atomics": lambda: cmd_atomics([c.name]),
        "sigma": lambda: cmd_sigma([c.name]),
    }
    for name in names:
        if name in skip:
            results.append((name, "skipped", "-" + name))
            print(f"  {'skip':6} {name}")
            if name == "queries" and ask:
                _ask_placement(c)
            if name == "pull":
                _step("sync", lambda: cmd_sync([c.name]) or "re-read the rules in rules/", log, results)
            continue
        if plan[name] is None:
            why = "no SecOps API in environment.env (drop exports in inputs/)" if name == "queries" else "not installed (yadda setup)"
            results.append((name, "n/a", why))
            print(f"  {'n/a':6} {name:11}        {why}")
            if name == "queries" and ask:
                _ask_placement(c)
            continue
        _step(name, plan[name], log, results, c.name)
        if name == "queries" and ask:
            _ask_placement(c)
        if name == "pull" and results[-1][1] == "FAILED":
            _step("sync", lambda: cmd_sync([c.name]) or "pull failed: using the rules already in rules/", log, results)
    results = _with_earlier(out, results)
    # outputs: always
    _step("dashboard", lambda: _dashboard(c), log, results)
    _step("workbook", lambda: build_workbook(c, results), log, results)
    write_readme(c, results)
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"\n########## finished {dt.datetime.now():%Y-%m-%d %H:%M}\n")
    latest = HOME / "output" / c.name / "latest"
    if latest.exists():
        _rmtree(latest)
    shutil.copytree(out, latest, ignore=shutil.ignore_patterns(".dettect"))
    headline(c)
    print(f"\nopen: {out / f'1_{c.name}_dashboard.html'}\n      {out / f'2_{c.name}_coverage.xlsx'}"
          f"\n(also copied to {latest}; details of every step in run_log.txt)")
    if any(r[1] == "FAILED" for r in results):
        sys.exit(1)


def _ask_placement(c: Path) -> None:
    """--ask: place the log types the platform table doesn't know, with the evidence the inventory gives."""
    from delib.placement import ask
    from delib.routes import inventory_file, observed
    inv = inventory_file(c)
    if inv is None:
        print("--ask: no telemetry inventory in the inputs folder, so there is nothing to place yet")
        return
    obs = observed(inv)
    lts = obs["log_types"]
    todo = [(lt, ev, "Event types: " + ", ".join(e for e, _ in lts[lt]["event_types"].most_common(5))
             + (f". Hosts: {', '.join(sorted(obs['host_os'][lt]))}" if lt in obs["host_os"] else ""))
            for lt, ev in sorted(obs["unplaced"].items(), key=lambda x: -x[1])]
    ask(c.name, todo)


def _with_earlier(out: Path, results: list) -> list:
    """Report a step skipped now but done earlier today as done then, so a partial re-run doesn't hide it from the
    day's README and workbook. Kept in <date>/steps.json."""
    f = out / "steps.json"
    try:
        done = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    except ValueError:
        done = {}
    now = f"{dt.datetime.now():%H:%M}"
    merged = []
    for name, status, note in results:
        if status == "skipped" and done.get(name, {}).get("status") == "ok":
            d = done[name]
            merged.append((name, "ok", f"{d['note']} (earlier run, {d['time']})"))
            continue
        if status in ("ok", "FAILED"):
            done[name] = {"status": status, "note": note, "time": now}
        merged.append((name, status, note))
    write_text(f, json.dumps(done, indent=1))
    return merged


def _layers(c: Path) -> str:
    from delib import layers
    a = assessment(c)
    made = [layers.detection_state(c, a["rows"], a["plats"]), layers.threats(c, a["tp"], a["plats"])]
    return f"{c.name}: " + ", ".join(f.name for f in made if f)


def _dashboard(c: Path) -> str:
    from delib.dashboard import cmd_dashboard
    cmd_dashboard([c.name])
    return f"1_{c.name}_dashboard.html"


# ---------------------------------------------------------------- one assessment, shared by every output
def assessment(c: Path) -> dict:
    from delib.analysis import _analysis
    from delib.attack import tech_index
    from delib.facts import scope_states
    from delib.priorities import _threat_priorities
    from delib.routes import inventory_file, observed, platform_summary
    from delib.telemetry import _dc_sources, _mapping
    rows, in_scope, plats = scope_states(c)
    measurable = set(_dc_sources(_mapping()))
    obs = observed(inventory_file(c))
    an = _analysis(c)
    tp = _threat_priorities(c, rows, in_scope, plats)
    users = {r["id"]: len(r["users"]) for r in tp["rows"]} if tp else {}
    from delib.analysis import technique_support
    from delib.procedures import threat_context
    return {"rows": rows, "in_scope": in_scope, "plats": plats, "obs": obs, "an": an, "tp": tp, "users": users,
            "platforms": platform_summary(in_scope, plats, obs, measurable), "ti": tech_index(),
            "support": technique_support(an["facts"]), "tc": threat_context(c)}


def rests_on(support: list) -> str:
    """'r02_lsass (1 technique), r09_broad (6 techniques, noisy)' - what a technique's detection rests on."""
    return "; ".join(f"{s['rule']} ({s['tags']} technique{'s' if s['tags'] > 1 else ''}, {s['state']}"
                     f"{', noisy' if s['noisy'] else ''})" for s in support)


QUOTA = {"1 telemetry": 8, "2 fix rule": 6, "3 write rule": 12, "4 validate": 6}   # per kind, so no kind crowds out the rest


def unlocks_text(x: dict) -> str:
    n = x["unlocks"]
    return "untagged rule: no technique counted yet" if not n else "" if n == 1 else f"{n} techniques"


def balanced(actions: list, limit: int) -> list:
    """The first `limit` actions, taking from each kind in turn so a short list still shows every kind. Actions that
    unlock no technique (e.g. fixing an untagged rule) come last."""
    out = []
    for pool in ([x for x in actions if x.get("unlocks", 1)], [x for x in actions if not x.get("unlocks", 1)]):
        by = defaultdict(list)
        for x in pool:
            by[x["kind"]].append(x)
        while len(out) < limit and any(by.values()):
            for k in sorted(by):
                if by[k] and len(out) < limit:
                    out.append(by[k].pop(0))
    return sorted(out, key=lambda x: (not x.get("unlocks", 1), x["kind"]))     # unlocking nothing: last


def next_actions(c: Path, a: dict, limit: int = 40) -> list[dict]:
    """The to-do list: what to do, why, and what it unlocks; most useful first within each kind, capped by QUOTA."""
    from delib.analysis import _review
    from delib.facts import _rule_facts
    from delib.sigma import candidates
    from delib.validation import _art_depth
    out, users, names = [], a["users"], {t["id"]: t["name"] for t in a["in_scope"].values()}
    n_threat = lambda ts: sum(1 for t in ts if users.get(t))
    # 1. telemetry: platforms with nothing seen, then the inputs that would complete the most routes
    tel = []
    if not a["obs"]["has_inventory"]:
        tel.append({"kind": "1 telemetry", "action": "Export the telemetry inventory into inputs/",
                    "why": "without it nothing can be said about what the environment sends (every technique is 'can't tell')",
                    "unlocks": len(a["rows"]), "threat_used": n_threat([r["id"] for r in a["rows"]]),
                    "how": "run shared/queries/telemetry_inventory.yaral in SecOps, save the CSV in environments/<environment>/inputs/"})
    for p in (a["platforms"] if a["obs"]["has_inventory"] else []):
        if not p["observed"] and p["routes"]:
            tel.append({"kind": "1 telemetry", "action": f"Nothing from {p['platform']} is seen in SecOps",
                        "why": f"{p['routes']} in-scope techniques have a MITRE detection route on {p['platform']}; "
                               "either the environment doesn't use it or it isn't forwarded (the SIEM can't tell which)",
                        "unlocks": p["routes"], "threat_used": "", "how": "find out whether it is used; if it is, onboard it"})
    miss = []
    for p in a["platforms"]:
        if not p["observed"]:
            continue
        for m in p["missing"][:8]:
            if m["completes"]:
                miss.append((p["platform"], m))
    for plat, m in sorted(miss, key=lambda x: (-len(x[1]["completes"]), -n_threat(x[1]["completes"]))):
        enable = m.get("enable") or []
        if enable and m.get("by_source"):
            lts = ", ".join(m["carriers"][:3])
            tel.append({"kind": "1 telemetry", "action": f"Check '{m['dc']}' in {lts} ({plat})",
                        "why": f"{lts} is in the SIEM, but none of its events give '{m['dc']}' (MITRE's source: "
                               f"{', '.join(enable)}). It is the only input these routes are missing",
                        "unlocks": len(m["completes"]), "threat_used": n_threat(m["completes"]),
                        "how": "enable the events that carry it (audit policy / collection), or, if they already arrive, "
                               "add them to shared/udm_event_type_to_data_component.csv; then re-run"})
            continue
        if m.get("onboard") and not enable:
            alt = m.get("alt")
            tel.append({"kind": "1 telemetry", "action": f"Onboard {m['onboard']} for {plat} ('{m['dc']}')",
                        "why": f"MITRE's main source for '{m['dc']}' ({m['top_sources'][0]}) is not in the SIEM; it is the "
                               "only input missing from these techniques' routes"
                               + (f". MITRE also names {alt['source']}, and {', '.join(alt['log_types'])} is already sent"
                                  if alt else ""),
                        "unlocks": len(m["completes"]), "threat_used": n_threat(m["completes"]),
                        "how": "deploy / forward it to SecOps, then re-run"
                               + (f"; or check which {', '.join(alt['log_types'])} events carry it (enable them, or add "
                                  "them to shared/udm_event_type_to_data_component.csv)" if alt else "")})
            continue
        tel.append({"kind": "1 telemetry",
                    "action": (f"Enable '{m['dc']}' for {plat}: {', '.join(enable[:3])}" if enable
                               else f"Get '{m['dc']}' for {plat}" + (f" ({m['product']})" if m["product"] else "")),
                    "why": "the only missing input of MITRE's detection route for these techniques"
                           + (f" (MITRE names: {', '.join(m['top_sources'])})" if m["top_sources"] else ""),
                    "unlocks": len(m["completes"]), "threat_used": n_threat(m["completes"]),
                    "how": (f"{', '.join(m['carriers'][:3])} {'is' if len(m['carriers']) == 1 else 'are'} already in the SIEM; "
                            f"turn on {', '.join(enable)} (audit policy / event collection, or the parser for it), then re-run")
                           if enable
                           else "onboard the log source, then re-run"})
    out += tel[:QUOTA["1 telemetry"]]
    # 2. rules that can't work or are noisy
    inv = inputs.current(c, "inventory")
    from delib.telemetry import _read_inventory
    fix = []
    decided = {}
    if (c / "rule_review.csv").exists():
        decided = {r["rule"]: r for r in read_csv(c / "rule_review.csv")[1] if (r.get("decision") or "").strip()}
    for r in _review(c, _rule_facts(c), _read_inventory(inv) if inv else []):
        d = decided.get(r["rule"])
        if d and (d.get("reasons") or "") == r["reasons"]:
            continue                                # you decided on exactly these reasons already
        if r["priority"] == "high":
            fix.append({"kind": "2 fix rule", "action": f"Fix rule {r['rule']}", "why": r["reasons"],
                        "unlocks": len(r["techniques"].split(", ")) if r["techniques"] else 0,
                        "threat_used": n_threat(r["techniques"].split(", ")), "how": "rule_review.csv"})
    out += sorted(fix, key=lambda x: (-(x["threat_used"] or 0), -x["unlocks"]))[:QUOTA["2 fix rule"]]
    # 3. rules to write: every input of a route seen, then routes one input short (a rule can use what is there)
    cand = Counter(t for row in candidates(c) for t in (row.get("covers") or "").split())
    # most threat-used first; at equal use, all inputs seen before one input short
    order = lambda r: (-users.get(r["id"], 0), r["state"] != "buildable", -cand.get(r["id"], 0), -r["prev"])
    from delib.facts import detected_on
    from delib.routes import RANK

    def other_route(r):
        """A route with every input seen on a platform the detecting rules don't cover (e.g. detected only by
        SaaS rules while the Windows route is fully supported); None if there is none."""
        if r["state"] not in ("detected", "validated") or r["state"] == "validated":
            return None
        cands = [rt for rt in r.get("routes") or [] if rt["level"] == "all" and not detected_on(r, {rt["platform"]})]
        return max(cands, key=lambda rt: RANK[rt["level"]], default=None)
    write = []
    for r in sorted((r for r in a["rows"] if r["state"] == "buildable" or (r["state"] == "thin" and r.get("one_short"))
                     or other_route(r)), key=order):
        b = other_route(r) or r.get("route") or {}
        full = r["state"] in ("buildable", "detected")
        on = ", ".join(sorted(r.get("detected_on") or []))
        write.append({"kind": "3 write rule", "action": f"Write a rule for {r['id']} {names.get(r['id'], '')}"
                                                       + (f" on {b.get('platform')}" if r["state"] == "detected" else ""),
                      "why": (f"detected only on {on}; every input of MITRE's {b.get('platform', '')} route is seen" if r["state"] == "detected"
                              else f"every input of MITRE's {b.get('platform', '')} route is seen ({b.get('seen')}/{b.get('needed')})" if full
                              else f"{b.get('seen')}/{b.get('needed')} inputs of MITRE's {b.get('platform', '')} route seen; "
                                   f"only '{', '.join(r.get('missing') or ['?'])}' missing - a rule can use what is there"),
                      "unlocks": 1, "threat_used": users.get(r["id"], 0),
                      "how": f"{cand[r['id']]} Sigma candidate(s) ready in 4_sigma_candidates" if cand.get(r["id"])
                             else "no Sigma candidate: write one (MITRE's analytic describes what to look for)"})
    out += write[:QUOTA["3 write rule"]]
    # 4. validate what is detected but untested
    from delib.facts import ANY
    from delib.validation import ART_PLATFORMS, _load_validation
    art = _art_depth(c)
    tests = defaultdict(list)
    for v in _load_validation(c):
        if v["result"] != "n/a":
            tests[v["technique"]].append(v)
    val = []
    for r in sorted((r for r in a["rows"] if r["state"] == "detected"), key=lambda r: -users.get(r["id"], 0)):
        av = art.get(r["id"], {})
        if av.get("fired") or av.get("missed"):
            continue
        on = r.get("detected_on") or set()
        arts = None if (not on or ANY in on) else {x for p in on for x in ART_PLATFORMS.get(p, [])}
        usable = [v for v in tests[r["id"]] if arts is None or v.get("art_platform") in arts]
        if usable:                                  # only tests that run where the detecting rules look
            val.append({"kind": "4 validate", "action": f"Test {r['id']} {names.get(r['id'], '')} with Atomic Red Team",
                        "why": "detected (fired recently), not yet proven by a test"
                               + (f"; tests on {', '.join(sorted(on))} only, where its rules look" if arts is not None else ""),
                        "unlocks": 1, "threat_used": users.get(r["id"], 0),
                        "how": f"{len(usable)} tests in validation.csv (e.g. Invoke-AtomicTest {r['id']} -TestGuids {usable[0]['test_guid']}); "
                               "record with yadda test, then yadda score ... 4"})
    out += val[:QUOTA["4 validate"]]
    return balanced(out, limit)


def _technique_rows(a: dict) -> list[list]:
    from delib.facts import STATES
    label = {k: l for k, l, _, _ in STATES}
    out = []
    for r in sorted(a["rows"], key=lambda r: r["id"]):
        b = r.get("route")
        missing = [i["dc"] + (f" ({', '.join(i['sources'][:2])})" if i["sources"] else "")
                   for i in (b["inputs"] if b else []) if i["measurable"] and not i["seen"]]
        prod = a["an"]["product"].get(r["id"], {})
        out.append([r["id"], r["name"], ", ".join(r["tactics"]), label[r["state"]]
                    + (" - one input short" if r.get("one_short") and r["state"] == "thin" else ""), r["score"],
                    a["users"].get(r["id"], 0), r["prev"], b["platform"] if b else "",
                    f"{b['seen']}/{b['needed']}" if b else "", "; ".join(missing),
                    rests_on(a["support"].get(r["id"], [])) or "; ".join(x.replace("SecOps: ", "") for x in r["rules"]),
                    ("any platform (rule names no log type)" if "*" in (r.get("detected_on") or set())
                     else ", ".join(sorted(r.get("detected_on") or []))) if r["state"] in ("validated", "detected") else "",
                    ", ".join(f"{k} ({v:,})" for k, v in sorted(prod.items(), key=lambda x: -x[1]))])
    return out


def build_workbook(c: Path, results: list) -> str:
    """2_<c>_coverage.xlsx: every table as a sheet (the CSV of each is in data/)."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from delib.analysis import cmd_rules
    from delib.priorities import _threat_list, cmd_priorities
    cmd_rules([c.name, "25"])                           # writes data/rule_ranking.csv
    if _threat_list(c):
        cmd_priorities([c.name, "25"])                  # writes data/threat_priorities.csv, threat_data_needs.csv
    a = assessment(c)
    data = out_dir(c, "data")
    write_rows(data / "funnel.csv", ["stage", "techniques", "% of in scope", "meaning"],
               [[label, val if hi is None else f"{val}-{hi}",
                 "" if i == 0 else f"{100 * val / (a['an']['ceiling'] or 1):.1f}%"
                 + ("" if hi is None else f"-{100 * hi / (a['an']['ceiling'] or 1):.1f}%"), desc]
                for i, (label, val, desc, hi) in enumerate(a["an"]["funnel"])])
    plat_rows = [[p["platform"], "seen" if p["observed"] else "not seen in SecOps",
                  ", ".join(f"{k} ({v:,})" for k, v in sorted(p["log_types"].items(), key=lambda x: -x[1])),
                  p["routes"], p["all"], p["some"], p["none"], p["unseen"], p["unknown"],
                  "; ".join(f"{m['dc']} -> completes {len(m['completes'])}" for m in p["missing"][:5])]
                 for p in a["platforms"]]
    write_rows(data / "telemetry_seen.csv", ["platform", "status", "log types seen (events)", "techniques with a MITRE route",
                                              "routes: all inputs seen", "some inputs", "no inputs", "platform/product not seen", "can't tell",
                                              "missing inputs that would complete the most routes"], plat_rows)
    acts = next_actions(c, a)
    write_rows(data / "next_actions.csv", ["kind", "action", "why", "techniques unlocked", "of them used by threat groups", "how"],
               [[x["kind"], x["action"], x["why"], x["unlocks"], x["threat_used"], x["how"]] for x in acts])
    write_rows(data / "techniques.csv", ["technique", "name", "tactics", "state", "score", "threat groups using it",
                                         "ATT&CK groups/campaigns", "best MITRE route (platform)", "route inputs seen",
                                         "missing inputs (MITRE log sources)",
                                         "detection rests on (rule: techniques it is tagged with, state)",
                                         "detected on (platforms of the firing rules)",
                                         "security-product detections, 30 days (not counted)"], _technique_rows(a))
    write_threat_context(data, a)
    _layers(c)
    if (c / "validation.csv").exists():
        head, body = read_csv(c / "validation.csv")
        from delib.facts import ANY
        from delib.validation import ART_PLATFORMS
        on = {r["id"]: r.get("detected_on") or set() for r in a["rows"]}

        def fits(r):            # can this test fire the rules that detect the technique (same platform)?
            ps = on.get(r.get("technique", ""), set())
            if not ps or ANY in ps:
                return "yes"
            return "yes" if r.get("art_platform") in {x for p in ps for x in ART_PLATFORMS.get(p, [])} else \
                f"no - its rules are on {', '.join(sorted(ps))}"
        write_rows(data / "validation_lab.csv", head + ["lab command", "can fire the detecting rules"],
                   [[r.get(h, "") for h in head] + [f"Invoke-AtomicTest {r.get('technique', '')} -TestGuids {r.get('test_guid', '')}"
                                                    if r.get("test_guid") else "", fits(r)] for r in body])
    sheets = [
        ("Funnel", data / "funnel.csv", "Coverage funnel: every % is of the in-scope techniques (all ATT&CK techniques on the environment's platforms)."),
        ("Telemetry seen", data / "telemetry_seen.csv", "Per ATT&CK platform: what SecOps shows, and how many MITRE detection routes it supports. 'Not seen' means not in the SIEM - not that the environment lacks it."),
        ("Next actions", data / "next_actions.csv", "The to-do list, most useful first: telemetry to get, rules to fix, rules to write, detections to validate."),
        ("Techniques", data / "techniques.csv", "Every in-scope ATT&CK Enterprise technique with its state and the closest MITRE detection route."),
        ("Rules", data / "rule_ranking.csv", "Enabled rules: most useful first, and the ones that need tuning."),
        ("Rule review", c / "rule_review.csv", "Rules that need a person to look at them (your decisions are kept in environments/<environment>/rule_review.csv)."),
        ("Threat priorities", data / "threat_priorities.csv", "Techniques the environment's threat groups (THREATS=) use, P1-P3."),
        ("Threat data needs", data / "threat_data_needs.csv", "ATT&CK data types those techniques need."),
        ("Threat software", data / "threat_software.csv", "The tools, malware and campaigns ATT&CK links to the environment's threats, and how many of their techniques are detected. A rule on a tool's behaviour can cover several techniques."),
        ("Procedures", data / "procedures.csv", "ATT&CK procedure examples: how each of those tools and groups performs each technique (what a rule would look for), gaps first."),
        ("Attack flows", data / "attack_flows.csv", "Real intrusions from MITRE CTID's Attack Flow corpus as ordered steps: how many are detected and the first step that would be seen. Flows naming the environment's threats come first."),
        ("Attack flow steps", data / "attack_flow_steps.csv", "Every step of every flow with the environment's state for its technique."),
        ("Inferred (TIE)", data / "inferred_techniques.csv", "Techniques MITRE CTID's Technique Inference Engine predicts the threats also use (trained on CTI reports). A hint where to look next: inferred, never counted."),
        ("Product detections", data / "product_detections.csv", "ATT&CK techniques security products in SecOps labelled their own alerts with (last 30 days). Shown separately: a product detection is not a SIEM rule."),
        ("Validation", data / "validation_lab.csv", "Atomic Red Team tests: what to run (the Invoke-AtomicTest command), and the results recorded with yadda test."),
        ("Sigma candidates", None, "SigmaHQ rules converted to YARA-L for gaps: not counted until deployed."),
        ("Robustness", c / "robustness_rules.csv", "MITRE Detection Coverage Calculator per rule."),
    ]
    from delib.sigma import candidates
    wb = Workbook()
    readme = wb.active
    readme.title = "Read me"
    from delib.attack import attack_version
    readme.append([f"{c.name}: detection coverage, {dt.date.today()}"])
    readme.append([f"MITRE ATT&CK Enterprise v{attack_version()} - platforms assessed: {', '.join(sorted(a['plats']))}. "
                   "ICS and Mobile matrices are not assessed."])
    readme.append([])
    readme.append(["Sheet", "What it is"])
    hdr_fill, bold = PatternFill("solid", fgColor="DDE7F3"), Font(bold=True)
    for name, src, what in sheets:
        if name == "Sigma candidates":
            rows = candidates(c)
            head, body = (list(rows[0]) if rows else []), rows
        elif src and Path(src).exists():
            head, body = read_csv(src)
        else:
            continue
        readme.append([name, what])
        ws = wb.create_sheet(name[:31])
        ws.append(head)
        for r in body:
            ws.append([_cell(r.get(h, "")) for h in head])
        for cell in ws[1]:
            cell.font, cell.fill = bold, hdr_fill
        ws.freeze_panes = "A2"
        if ws.max_row > 1:
            ws.auto_filter.ref = ws.dimensions
        for col in ws.columns:
            width = max((len(str(x.value or "")) for x in list(col)[:200]), default=8)
            ws.column_dimensions[col[0].column_letter].width = min(max(width + 2, 8), 70)
    readme.append([])
    readme.append(["Step", "Result", "Note"])
    for r in results:
        readme.append(list(r))
    readme["A1"].font = Font(bold=True, size=14)
    readme.column_dimensions["A"].width, readme.column_dimensions["B"].width = 22, 120
    f = out_dir(c) / f"2_{c.name}_coverage.xlsx"
    tmp = f.with_name(f".{f.name}.tmp")
    wb.save(tmp)
    try:
        os.replace(tmp, f)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        die(f"can't write {f} - it is probably open in Excel. Close it and run again.")
    return f.name


def write_threat_context(data: Path, a: dict) -> None:
    """The threat-context tables (procedures, Attack Flow, TIE) and security-product detections as CSVs in data/."""
    from delib.facts import STATES
    label = {k: l for k, l, _, _ in STATES}
    lab = lambda st: label.get(st, st)
    tc, names = a["tc"], {t["id"]: t["name"] for t in a["ti"]["techs"].values()}
    sw = [[r["name"], r["id"], r["type"], ", ".join(r["used_by"]), r["techniques"], r["detected"],
           f"{100 * r['detected'] / r['techniques']:.0f}%" if r["techniques"] else "-",
           ", ".join(f"{lab(k)} {v}" for k, v in sorted(r["states"].items(), key=lambda x: -x[1])),
           r["out_of_scope"], ", ".join(r["gaps"][:12])] for r in tc["software"] + tc["campaigns"]]
    write_rows(data / "threat_software.csv", ["name", "ATT&CK id", "type", "used by (environment threats)",
                                              "techniques in scope", "detected", "% detected", "states",
                                              "techniques on other platforms", "gaps (closest to detected first)"], sw)
    write_rows(data / "procedures.csv", ["technique", "technique name", "state", "by", "kind", "used by", "procedure (ATT&CK)"],
               [[p["technique"], names.get(p["technique"], ""), lab(p["state"]), p["by"], p["kind"], p["used_by"],
                 p["procedure"]] for p in tc["procedures"]])
    write_rows(data / "attack_flows.csv", ["flow", "names the environment's threat", "steps", "actions", "actions on the environment's platforms",
                                           "detected", "first step detected", "undetected steps before it", "description", "file"],
               [[f["name"], ", ".join(f["relevant_to"]), f["total_steps"], f["actions"], f["judged"], f["covered"],
                 f["first_seen_step"] or "never",
                 ", ".join(f"{s['step']}:{s['technique']}" for s in f["steps"]
                           if s["state"] != "out of scope" and (f["first_seen_step"] is None or s["step"] < f["first_seen_step"]))[:400],
                 f["description"], f["file"]] for f in tc["flows"]])
    write_rows(data / "attack_flow_steps.csv", ["flow", "step", "technique", "technique name", "state", "action", "what happened"],
               [[f["name"], s["step"], s["technique"], names.get(s["technique"], ""), lab(s["state"]), s["name"],
                 s["description"]] for f in tc["flows"] for s in f["steps"]])
    write_rows(data / "inferred_techniques.csv", ["threat", "rank", "technique", "technique name", "state", "TIE score",
                                                  "inferred from (techniques ATT&CK lists)"],
               [[r["threat"], r["rank"], r["technique"], names.get(r["technique"], ""), lab(r["state"]), r["score"],
                 r["from"]] for r in tc["inferred"]])
    det = {r["id"]: r["state"] for r in a["rows"]}
    write_rows(data / "product_detections.csv", ["technique", "technique name", "SIEM state", "log type", "events (30 days)"],
               [[t, names.get(t, ""), lab(det.get(t, "")), lt, n] for t, lts in sorted(a["an"]["product"].items())
                for lt, n in sorted(lts.items(), key=lambda x: -x[1])])


def _cell(v):
    s = str(v)
    if s.lstrip("-").isdigit() and len(s) < 15:
        return int(s)
    return s


def write_readme(c: Path, results: list) -> None:
    from delib.attack import attack_version
    found = inputs.files(c)
    lines = [f"{c.name} - yadda run {dt.datetime.now():%Y-%m-%d %H:%M}",
             f"MITRE ATT&CK Enterprise v{attack_version()} (ICS and Mobile are not assessed)", "",
             *[f"{name:34} {what}" for name, what in (
                 (f"1_{c.name}_dashboard.html", "start here: headline, telemetry seen, the funnel, the ATT&CK matrix, next actions"),
                 (f"2_{c.name}_coverage.xlsx", "every table, one sheet each (the 'Read me' sheet explains them)"),
                 ("3_navigator_layers/", "open in https://mitre-attack.github.io/attack-navigator/"),
                 ("4_sigma_candidates/", "converted SigmaHQ rules for gaps (not counted until deployed)"),
                 ("data/", "the same tables as CSV"),
                 ("run_log.txt", "everything each step printed (every run today, appended)"))
                 if (out_dir(c) / name.rstrip("/")).exists() or name == "run_log.txt"], "",
             "Exports used (environments/" + c.name + "/inputs/):"]
    for k, desc in inputs.KINDS.items():
        f = found[k][0] if found[k] else None
        lines.append(f"  {desc}: {f.name + ' (' + str(dt.date.fromtimestamp(f.stat().st_mtime)) + ')' if f else 'none'}")
    if found["unknown"]:
        lines.append("  ignored (not a SecOps export yadda knows): " + ", ".join(f.name for f in found["unknown"]))
    lines += ["", "Steps:"] + [f"  {n:11} {s:7} {note}" for n, s, note in results]
    write_text(out_dir(c) / "README.txt", "\r\n".join(lines) + "\r\n")


def headline(c: Path) -> None:
    """What to read first, in the terminal."""
    a = assessment(c)
    st = Counter(r["state"] for r in a["rows"])
    print(f"\n{c.name}: {len(a['rows'])} ATT&CK Enterprise techniques in scope ({', '.join(sorted(a['plats']))})")
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    if not env.get("PLATFORMS", "").strip():
        print(f"  NOTE: no PLATFORMS= in environment.env, so every ATT&CK platform is assessed. Set the ones {c.name} has.")
    for p in a["platforms"]:
        if p["routes"]:
            seen = "seen" if p["observed"] else "NOT SEEN in SecOps" if a["obs"]["has_inventory"] else "no inventory yet"
            print(f"  {p['platform']:18} {seen:18} routes: "
                  f"{p['all']} all inputs, {p['some']} some, {p['none']} none, {p['unseen']} product not seen")
    n = a["an"]["counts"]
    hand = (f"; {n['scored_by_hand']} more scored by hand without a SIEM rule (not counted)" if n["scored_by_hand"] else "")
    print(f"  detected by SIEM rules {n['detected_by_rules']} (validated {n['validated_by_rules']}){hand}")
    print(f"  limited {st['limited']}, unverified {st['unverified']}, data-no-rule {st['buildable']}, some data {st['thin']} "
          f"({n['one_short']} one input short), no data seen {st['blind']}, platform not seen {st['unseen']}, "
          f"can't tell {st['unknown']}")
    if n["product_export"]:
        print(f"  security products in SecOps detected {n['product_detected']} in-scope techniques "
              f"({n['product_only']} with no SIEM detection) - shown separately, not counted")
    from delib.routes import telemetry_notes
    for kind, text in telemetry_notes(a["obs"], a["platforms"], c.name):
        if kind in ("place", "idp"):
            print(f"  NOTE: {text}")
    acts = balanced(next_actions(c, a), 5)
    if acts:
        print("  next:")
        for x in acts:
            print(f"   - {x['action']}" + (f" ({unlocks_text(x)})" if unlocks_text(x) else ""))
