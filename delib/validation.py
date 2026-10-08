"""validation - Atomic Red Team tests for an environment's techniques (from ART's CSV indexes,
https://github.com/redcanaryco/atomic-red-team) and the results recorded in validation.csv."""
from __future__ import annotations

import re

import csv
import datetime as dt
from collections import defaultdict
from pathlib import Path
from delib.config import envdir, die, download, raw_url, read_csv, read_env, TOOLS, write_csv
from delib.attack import _scope, attack, resolve
from delib.facts import load_techniques


# ---------------------------------------------------------------- Atomic Red Team variant tracking
ART_PATH = "atomics/Indexes/Indexes-CSV/{}-index.csv"      # in atomic-red-team, at the commit pinned in tools.lock


ART_PLATFORMS = {"Windows": ["windows"], "Linux": ["linux"], "macOS": ["macos"], "Office Suite": ["office-365", "google-workspace"],
                 "Identity Provider": ["azure-ad"], "SaaS": ["google-workspace", "office-365"], "IaaS": ["iaas"],
                 "Containers": ["containers"], "ESXi": ["esxi"]}


VALIDATION_FIELDS = ["technique", "test_number", "test_guid", "test_name", "art_platform", "executor", "result", "rule",
                     "tested_on", "notes"]


def _art_index(platforms: set, refresh: bool = False) -> dict:
    """technique -> {guid: test} for ART tests on the environment's platforms (one row per test, not per tactic)."""
    a = attack()
    out = defaultdict(dict)
    for p in sorted({x for pl in platforms for x in ART_PLATFORMS.get(pl, [])}):
        f = TOOLS / "art" / f"{p}-index.csv"
        if refresh or not f.exists():
            print(f"downloading Atomic Red Team {p} index ...", flush=True)
            download(raw_url("atomic-red-team", ART_PATH.format(p)), f)
        for r in csv.DictReader(f.open(encoding="utf-8")):
            tid = a["replaced"].get(r["Technique #"], r["Technique #"])
            out[tid].setdefault(r["Test GUID"], {"technique": tid, "test_number": r["Test #"], "test_guid": r["Test GUID"],
                                                 "test_name": r["Test Name"], "art_platform": p,
                                                 "executor": r["Executor Name"]})
    return out


def _load_validation(c: Path) -> list[dict]:
    """validation.csv rows; missing columns are filled in blank and extra columns are kept."""
    f = c / "validation.csv"
    if not f.exists():
        return []
    rows = read_csv(f)[1]
    for r in rows:
        for k in VALIDATION_FIELDS:
            r[k] = r.get(k) or ""
        r["result"] = r["result"].strip().lower()            # 'Fired' typed in Excel counts as fired
    return rows


def _save_validation(c: Path, rows: list[dict]) -> None:
    def num(v):
        m = re.match(r"\d+", str(v or ""))
        return (int(m.group()) if m else 0, str(v or ""))
    rows.sort(key=lambda r: (r["technique"], num(r["test_number"]), r["art_platform"]))
    write_csv(c / "validation.csv", VALIDATION_FIELDS, rows)


def cmd_atomics(args):
    """yadda atomics <environment> [T-ids | --ruled | --threats]  - list ART tests to run, add them to validation.csv"""
    if not args:
        die("usage: yadda atomics <environment> [T1053.005 ... | --ruled (default) | --threats]")
    c = envdir(args[0])
    have = load_techniques(c)
    sel = [a for a in args[1:] if not a.startswith("--")]
    if sel:
        techs, _ = resolve(sel)
    elif "--threats" in args:
        env = read_env(c / "environment.env")
        techs, _ = resolve([x.strip() for x in env.get("THREATS", "").split(",") if x.strip()] or die("no THREATS= in environment.env"))
    else:                                                    # default: techniques that have an enabled rule
        techs = sorted(t for t, v in have.items() if v["score"] >= 1)
    idx = _art_index(_scope(c))
    rows = _load_validation(c)
    known = {r["test_guid"] for r in rows}
    added, no_tests, cmds = 0, [], defaultdict(list)
    for tid in techs:
        tests = idx.get(tid, {})
        if not tests:
            no_tests.append(tid)
            continue
        for g, t in tests.items():
            if g not in known:
                rows.append({**t, "result": "", "rule": "", "tested_on": "", "notes": ""})
                added += 1
            r = next(x for x in rows if x["test_guid"] == g)
            if not r["result"]:
                cmds[(t["art_platform"], tid)].append(g)
    _save_validation(c, rows)
    print(f"{c.name}: {len(techs)} techniques, {added} new ART tests added to {c / 'validation.csv'}"
          f" ({sum(len(v) for v in cmds.values())} not yet run)")
    if no_tests:
        print(f"  no ART test for {len(no_tests)} of them on this environment's platforms: {', '.join(no_tests[:15])}"
              f"{' ...' if len(no_tests) > 15 else ''}")
    if cmds:
        print("\n  Run them in a test lab (Invoke-AtomicRedTeam), then record each result with: yadda test <environment> <guid> fired|missed")
        for (plat, tid), guids in sorted(cmds.items())[:60]:
            shell = "pwsh" if plat in ("linux", "macos") else "PS"
            print(f"  [{plat:7}] {shell}> Invoke-AtomicTest {tid} -TestGuids {','.join(guids)}")
        if len(cmds) > 60:
            print(f"  ... {len(cmds) - 60} more techniques - see validation.csv")


def cmd_test(args):
    """yadda test <environment> <guid|guid-prefix|T1053.005#2> fired|missed|n/a [rule] ["notes"]  - record an ART result"""
    if len(args) >= 3:
        args = [*args[:2], args[2].lower(), *args[3:]]
    if len(args) < 3 or args[2] not in ("fired", "missed", "n/a", "clear"):
        die('usage: yadda test <environment> <test guid (or first 8 chars) | T1053.005#2> fired|missed|n/a|clear [rule] ["notes"]')
    c, key, result = envdir(args[0]), args[1], args[2]
    rows = _load_validation(c) or die(f"no validation.csv - run: yadda atomics {c.name}")
    if "#" in key:
        tid, num = key.split("#", 1)
        hits = [r for r in rows if r["technique"] == tid.upper() and r["test_number"] == num]
    else:
        hits = [r for r in rows if r["test_guid"].lower().startswith(key.lower())]
    if len(hits) != 1:
        die(f"'{key}' matches {len(hits)} tests - give more of the GUID, or use T1053.005#<test number>")
    r = hits[0]
    r["result"] = "" if result == "clear" else result
    r["rule"] = args[3] if len(args) > 3 else r["rule"]
    r["notes"] = " ".join(args[4:]) if len(args) > 4 else r["notes"]
    r["tested_on"] = "" if result == "clear" else str(dt.date.today())
    _save_validation(c, rows)
    t_rows = [x for x in rows if x["technique"] == r["technique"]]
    fired = sum(1 for x in t_rows if x["result"] == "fired")
    tested = sum(1 for x in t_rows if x["result"] in ("fired", "missed"))
    print(f"{c.name} {r['technique']} test #{r['test_number']} '{r['test_name']}': {result}"
          f"  -> technique now {fired}/{tested} tested variants fired ({len(t_rows)} available)")


def _art_depth(c: Path) -> dict:
    out = defaultdict(lambda: {"available": 0, "fired": 0, "missed": 0})
    for r in _load_validation(c):
        d = out[r["technique"]]
        if r["result"] != "n/a":
            d["available"] += 1
        if r["result"] in ("fired", "missed"):
            d[r["result"]] += 1
    return out
