"""priorities - techniques to work on first, ranked by how many of the environment's threat groups use them
(THREATS= in environment.env), with the data each one still needs."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from delib.config import out_dir, _pct, envdir, die, read_env, write_rows
from delib.attack import EXTERNAL_DCS, PRE_TACTICS, _scope, resolve, tech_index
from delib.telemetry import _dc_sources, _mapping
from delib.routes import inventory_file
from delib.facts import CONTEXT_STATES, _states
from delib.validation import _art_index


def _threat_list(c: Path) -> list[tuple[str, str, set]]:
    """THREATS= in environment.env -> [(label, group id or '', techniques)]. A threat-intel file counts as one threat."""
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    out = []
    for item in [x.strip() for x in env.get("THREATS", "").split(",") if x.strip()]:
        tids, labels = resolve([item])
        gid = re.search(r"\((G\d{4}|C\d{4})\)$", labels[0]) if len(labels) == 1 else None
        out.append(("; ".join(labels) if len(labels) <= 2 else item, gid.group(1) if gid else "", set(tids)))
    return out


def _action(r: dict, assessed: bool, measurable: set) -> str:
    missing = sorted((r["need"] & measurable) - r["got"] - EXTERNAL_DCS)
    if r["outside"]:
        return "outside the environment's telemetry (pre-compromise): cover with threat intel / external monitoring"
    if not assessed:
        return "needs: " + (", ".join(sorted(r["need"] - EXTERNAL_DCS)) or "no ATT&CK data types listed")
    return {"validated": "covered and proven",
            "detected": "covered - prove it with Atomic Red Team (Validation sheet)",
            "limited": "tune the rule (noisy or narrow)",
            "unverified": "rule deployed - confirm it fires (yadda review)",
            "hand": "scored by hand, no SIEM rule: keep if another control covers it, else write a rule",
            "elsewhere": f"detected only on {', '.join(sorted(r.get('detected_on') or []))}: write a rule where this group would use it"
                         + (f" ({r['route']['platform']})" if r.get("route") else ""),
            "buildable": "write a rule - the data is already there",
            "thin": "write a rule; more data would help: " + ", ".join(missing[:3]),
            "blind": "enable the missing events: " + ", ".join(missing[:3]),
            "unseen": f"no {r['route']['platform'] if r.get('route') else ''} logs in the SIEM: ask whether it's used, onboard it if so",
            "unknown": "can't measure: needs " + ", ".join(sorted(r["need"] - r["got"] - EXTERNAL_DCS)[:3] or ["unmapped data"])}[r["state"]]


def _threat_priorities(c: Path, rows: list[dict], in_scope: dict, scope_plats: set) -> dict:
    """Techniques the environment's threat groups use, ranked by how many of those groups use them.
    Tiers: P1 = used by at least a third of the groups and at least 2 of them (with only 1 or 2 groups: used by all),
    P2 = 2+ groups, P3 = one group."""
    import math
    threats = _threat_list(c)
    n = len(threats)
    if not n:
        return {"n": 0, "threats": [], "rows": [], "tiers": {}, "off_platform": 0, "outside": [], "p1": 0}
    users = defaultdict(list)
    for label, gid, ts in threats:
        for t in ts:
            users[t].append(label.split(" (")[0])
    by_id = {r["id"]: r for r in rows}
    assessed = inventory_file(c) is not None       # judged against telemetry only once an inventory exists
    measurable = set(_dc_sources(_mapping()))
    p1 = n if n < 3 else max(2, math.ceil(n / 3))
    out, outside, off = [], [], 0
    for tid, who in users.items():
        t = tech_index()["techs"].get(tid)
        if t is None:
            continue
        pre = "PRE" in t["platforms"] or set(t["tactics"]) <= PRE_TACTICS
        if tid not in by_id and not pre:
            off += 1
            continue
        r = dict(by_id[tid]) if tid in by_id else {"id": tid, "name": t["name"], "tactics": t["tactics"], "state": "unknown",
                                                    "score": -1, "vis": 0, "need": set(t["dcs"]), "got": set(),
                                                    "prev": t["prevalence"], "rules": [], "comment": ""}
        r["outside"] = bool(pre or (t["dcs"] and t["dcs"] <= EXTERNAL_DCS))
        # a group's technique is judged where the group would use it (on hosts when it runs on hosts): a rule on
        # SaaS logs doesn't detect the group doing the same thing on a Windows host
        from delib.procedures import context_state, step_platforms
        if tid in by_id:
            r["state"] = context_state(r, step_platforms(tid) & scope_plats or step_platforms(tid))
        r["users"] = sorted(who)
        r["tier"] = "P1" if len(who) >= p1 else "P2" if len(who) >= 2 else "P3"
        r["assessed"] = assessed
        r["action"] = _action(r, assessed, measurable)
        (outside if r["outside"] else out).append(r)
    order = lambda r: (-len(r["users"]), -r["prev"], r["id"])
    out.sort(key=order)
    outside.sort(key=order)
    for i, r in enumerate(out, 1):
        r["rank"] = i
    tiers = {k: Counter(r["state"] for r in out if r["tier"] == k) for k in ("P1", "P2", "P3")}
    # Inputs of these techniques' MITRE routes, per platform, ranked by group-weighted techniques (once assessed:
    # only the inputs not seen). A Windows input and an Office Suite input are different things to onboard.
    data = defaultdict(lambda: {"techs": [], "weight": 0, "p1": 0, "mitre": set()})
    for r in out:
        if r["state"] in ("validated", "detected", "limited", "unverified", "hand", "elsewhere"):
            continue
        for rt in r.get("routes") or []:
            for i in rt["inputs"]:
                if not i["measurable"] or (assessed and i["seen"]):
                    continue
                d = data[(i["dc"], rt["platform"])]
                if r["id"] not in d["techs"]:
                    d["techs"].append(r["id"])
                    d["weight"] += len(r["users"])
                    d["p1"] += r["tier"] == "P1"
                d["mitre"] |= set(i["sources"])
    from delib.routes import log_type_platforms, platforms_of
    table, mapping = log_type_platforms(), _mapping()

    def provided_by(dc, plat):
        """SecOps events that carry this input on this platform: rows for one of the platform's log types first,
        then generic UDM event types; rows tied to another platform's log types are left out."""
        own, generic = [], []
        for x in mapping:
            if x["dc"] != dc:
                continue
            if x["lt"] is None:
                generic.append(x["label"])
            else:
                sample = x["lt"].pattern.split("|")[0].replace(".*", "")
                if plat in platforms_of(sample, table):
                    own.append(x["label"])
        return list(dict.fromkeys(own + generic))
    data_rank = [{"dc": dc, "platform": plat, **{k: v for k, v in val.items() if k != "mitre"}, "measurable": True,
                  "sources": sorted(val["mitre"]) + provided_by(dc, plat)}
                 for (dc, plat), val in sorted(data.items(), key=lambda kv: (-kv[1]["weight"], kv[0]))]
    uses = sum(len(r["users"]) for r in out)
    cov = lambda r: r["state"] in ("validated", "detected")
    return {"n": n, "threats": threats, "rows": out, "outside": outside, "data": data_rank, "off_platform": off, "tiers": tiers,
            "p1": p1, "assessed": assessed, "covered": sum(map(cov, out)),
            "weighted": (sum(len(r["users"]) for r in out if cov(r)) / uses) if uses else 0,
            "states": Counter(r["state"] for r in out)}


def _tier_label(tp: dict, k: str) -> str:
    n, p1 = tp["n"], tp["p1"]
    if k == "P1":
        return f"P1 - used by {p1}+ of {n} groups" if p1 < n else f"P1 - used by all {n}"
    return "P2 - used by 2+ groups" if k == "P2" else "P3 - used by one group"


def cmd_priorities(args):
    """yadda priorities <environment> [N] [--gaps] [--layer]  - techniques to prioritise, from the environment's threat groups"""
    if not args:
        die("usage: yadda priorities <environment> [N] [--gaps] [--layer]")
    c = envdir(args[0])
    top = next((int(a) for a in args[1:] if a.isdigit()), 30)
    scope_plats = _scope(c)
    in_scope = {tid: t for tid, t in tech_index()["techs"].items() if t["platforms"] & scope_plats}
    rows = _states(c, in_scope, scope_plats)[0]
    tp = _threat_priorities(c, rows, in_scope, scope_plats)
    if not tp["n"]:
        die(f"no THREATS= in {c / 'environment.env'}. Set it with: yadda actors --sector ... --country ... --environment {c.name} --set")
    out = tp["rows"]
    try:
        art = _art_index(scope_plats)
    except Exception:
        art = {}
    every = len({t for _, _, ts in tp["threats"] for t in ts})
    print(f"{c.name}: {tp['n']} threats (THREATS= in environment.env) use {every} ATT&CK techniques")
    extra = (f"; {tp['off_platform']} on other platforms (not listed)" if tp["off_platform"] else "") + \
            (f"; {len(tp['outside'])} pre-compromise (recon / resource development, not SIEM-detectable)" if tp["outside"] else "")
    print(f"  {len(out)} on the environment's platforms and detectable in its telemetry{extra}")
    if tp["assessed"]:
        st = tp["states"]
        print("\nCOVERAGE AGAINST THESE THREATS")
        print(f"  Techniques detected or validated   {tp['covered']:>4}/{len(out)}  {_pct(tp['covered'], len(out))}")
        print(f"  Weighted by groups using each      {tp['weighted'] * 100:>9.1f}%   (share of all group-technique uses you would detect)")
        print(f"  Data present, no rule              {st['buildable']:>4}        quickest wins")
        print(f"  No data seen (inputs missing)      {st['blind']:>4}")
        print(f"  Platform not seen in the SIEM      {st['unseen']:>4}")
        for k in ("P1", "P2", "P3"):
            t = tp["tiers"][k]
            tot = sum(t.values())
            if tot:
                print(f"  {_tier_label(tp, k):34} {tot:>4} techniques, detected {t['validated'] + t['detected']} ({_pct(t['validated'] + t['detected'], tot)}),"
                      f" data/no rule {t['buildable']}, some data {t['thin']}, no data seen {t['blind']}, platform not seen {t['unseen']}")
    else:
        print("\n  Not assessed yet (no rules or telemetry loaded): the list is the onboarding scope - what data and rules these threats need.")
    if tp["data"]:
        print(f"\n{'DATA TO ONBOARD' if not tp['assessed'] else 'MISSING DATA'}  (ranked by how much threat activity it makes visible; full list in the CSV)")
        print(f"  {'ATT&CK data type':32} {'techniques':>10} {'P1':>4} {'weight':>6}  provided by (event type / log type)")
        for d in tp["data"][:12]:
            prov = ", ".join(d["sources"][:3]) + (" ..." if len(d["sources"]) > 3 else "") if d["measurable"] else "(no mapping yet - add to the mapping CSV)"
            print(f"  {(d['dc'] + ' (' + d['platform'] + ')')[:40]:40} {len(d['techs']):>10} {d['p1']:>4} {d['weight']:>6}  {prov[:72]}")
    show = [r for r in out if r["state"] not in ("validated", "detected")] if "--gaps" in args else out
    print(f"\nPRIORITY LIST ({'gaps only, ' if '--gaps' in args else ''}top {min(top, len(show))} of {len(show)})")
    print(f"  {'#':>3} {'tier':4} {'technique':10} {'name':34} {'groups':>6} {'ATT&CK':>6}  {'status':14} action")
    for r in show[:top]:
        status = dict((k, l.split(" (")[0]) for k, l, _, _ in CONTEXT_STATES)[r["state"]] if r["assessed"] else "not assessed"
        print(f"  {r['rank']:>3} {r['tier']:4} {r['id']:10} {r['name'][:34]:34} {len(r['users']):>3}/{tp['n']:<2} {r['prev']:>6}  {status[:14]:14} {r['action'][:70]}")
    f = out_dir(c, "data") / "threat_priorities.csv"
    write_rows(f, ["rank", "tier", "technique", "name", "tactics", "groups_using", "of_threats", "threat_groups",
                   "attack_prevalence", "status", "action", "data_types_needed", "data_types_present", "rules", "art_tests"],
               [[r.get("rank", ""), "pre-compromise" if r["outside"] else r["tier"], r["id"], r["name"],
                 ", ".join(r["tactics"]), len(r["users"]), tp["n"], "; ".join(r["users"]), r["prev"],
                 dict((k, l) for k, l, _, _ in CONTEXT_STATES)[r["state"]] if r["assessed"] else "not assessed",
                 r["action"], "; ".join(sorted(r["need"])), "; ".join(sorted(r["got"])),
                 "; ".join(x.replace("SecOps: ", "") for x in r["rules"]), len(art.get(r["id"], []))]
                for r in out + tp["outside"]])
    fd = out_dir(c, "data") / "threat_data_needs.csv"
    write_rows(fd, ["data_type", "platform", "techniques", "p1_techniques", "group_weight", "mitre_log_sources_and_secops_events", "technique_ids"],
               [[d["dc"], d["platform"], len(d["techs"]), d["p1"], d["weight"], "; ".join(d["sources"]), " ".join(d["techs"])]
                for d in tp["data"]])
    print(f"\nfull list incl. pre-compromise: {f}\ndata needed per ATT&CK data type: {fd}")
    print(f"tiers: {_tier_label(tp, 'P1')}, P2 = 2+ groups, P3 = one group; ties broken by ATT&CK-wide use")
    if "--layer" in args:
        from delib import layers
        f = layers.threats(c, tp, scope_plats)
        print(f"Navigator layer: {f} (colour = state, score = how many threat groups use the technique)")
