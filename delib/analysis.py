"""analysis - the check, review, metrics and rules commands, and the coverage funnel and rule ranking they share."""
from __future__ import annotations

from delib.cache import per_environment
from delib import inputs

from collections import Counter, defaultdict
from pathlib import Path
from delib.config import _pct, envdir, DETECTED, die, out_dir, read_csv, read_env, write_csv, write_rows
from delib.attack import _scope, attack, resolve, tech_index
from delib.yaral import scope
from delib.telemetry import _mapping, _read_inventory, _row_dcs, present
from delib.facts import _rule_facts, _states, load_techniques, scope_states, thresholds
from delib.validation import _load_validation, _art_depth
from delib.robustness import _robustness, _robustness_rules
from delib.priorities import _threat_priorities


def cmd_check(args):
    """yadda check <environment> <T-ids | ATT&CK group/campaign | threat-intel yaml> [--layer]"""
    layer = "--layer" in args
    args = [a for a in args if a != "--layer"]
    if len(args) < 2:
        die("usage: yadda check <environment> <T1059.001 ... | APT29 | G0016 | redteam-q4.yaml> [--layer]")
    c = envdir(args[0])
    if args[1:] == ["--threats"]:
        items = [x.strip() for x in read_env(c / "environment.env").get("THREATS", "").split(",") if x.strip()]
        args = args[:1] + (items or [die(f"no THREATS= in {c / 'environment.env'}")])
    techs, labels = resolve(args[1:])
    have = load_techniques(c)
    names = attack()["names"]
    states = {r["id"]: r for r in scope_states(c)[0]}
    label = {"validated": "VALIDATED", "detected": "DETECTED", "limited": "LIMITED", "unverified": "UNVERIFIED",
             "hand": "BY HAND, NO RULE", "buildable": "DATA, NO RULE", "thin": "SOME DATA", "blind": "NO DATA SEEN", "unseen": "PLATFORM NOT SEEN",
             "unknown": "CAN'T TELL"}
    order = {v: i for i, v in enumerate(list(label.values()) + ["NOT IN SCOPE"])}
    rows, buckets = [], Counter()
    for t in techs:
        h, r = have.get(t, {}), states.get(t)
        status = label[r["state"]] if r else "NOT IN SCOPE"     # not on the environment's platforms
        buckets[status] += 1
        data = f"{len(r['got'])}/{len(r['need'])}" if r else "-"
        rows.append((status, t, names.get(t, "?")[:38], h.get("score", -1), data, str(h.get("date") or "")[:10],
                     ", ".join(x.replace("SecOps: ", "") for x in h.get("rules", []))[:45], str(h.get("comment", ""))[:40]))
    print(f"\n{c.name} vs {'; '.join(labels)}: {len(techs)} techniques")
    print("  " + "  ".join(f"{k}: {buckets[k]}" for k in order if buckets[k] or k in ("DETECTED", "DATA, NO RULE", "NO DATA SEEN")))
    print(f"\n  {'status':14} {'technique':10} {'name':38} {'det':>3} {'data':>5} {'scored':10} rules / evidence")
    for r in sorted(rows, key=lambda r: (order[r[0]], r[1])):
        print(f"  {r[0]:14} {r[1]:10} {r[2]:38} {r[3]:>3} {r[4]:>5} {r[5]:10} {r[6]}{' | ' + r[7] if r[7] else ''}")
    print("  data = inputs of its best MITRE detection route seen in the SIEM / inputs it needs")
    if layer:
        from delib import layers
        f = layers.check(c, "; ".join(labels), techs, states, _scope(c))
        print(f"\n  Navigator layer: {f} (open in ATT&CK Navigator)")


@per_environment(key=lambda facts, inventory: (id(facts), len(inventory)))
def _review(c: Path, facts: dict, inventory: list) -> list[dict]:
    """Rules that need a person to look at them, with the reasons and a priority."""
    p = present(inventory)
    sent_et, sent_lt = p["event_types"], p["log_types"]
    rob_rules = _robustness_rules(c)
    lab_hits = defaultdict(set)          # rule -> techniques whose lab tests it fired on (validation.csv)
    for v in _load_validation(c):
        if v["result"] == "fired" and v["rule"]:
            lab_hits[v["rule"].strip()].add(v["technique"])
    out = []
    for r in facts["rules"]:
        reasons, prio = [], 3
        def add(p, text):
            nonlocal prio
            reasons.append(text)
            prio = min(prio, p)
        if inventory and r["eventtypes"] and not (r["eventtypes"] & sent_et):
            add(1, f"cannot fire: needs event type {', '.join(sorted(r['eventtypes']))}, not received")
        if inventory and r["logtypes"] and not (r["logtypes"] & sent_lt):
            add(1, f"cannot fire: filters on log type {', '.join(sorted(r['logtypes']))}, not received")
        if r["noisy"]:
            add(1, f"noisy: {r['fp_pct']}% of {r['cases']} closed cases not malicious")
        if r.get("shared_name", 1) > 1:
            add(3, f"{r['shared_name']} enabled rules share this display name: the FP and log-type exports can't tell "
                   "them apart, so FP isn't scored for them - give them distinct names in SecOps")
        if r["state"] == "never fired":
            add(2, "never fired")
        elif r["state"] == "fired, date unknown":
            add(3, f"{r['count']} detections but the export has no detection time - re-export with detection_time")
        elif r["state"] == "stale":
            add(2, f"stale: last fired {r['last']}")
        if not r["techniques"]:
            add(2, "no usable ATT&CK tag (invisible in coverage)")
        if r["retagged"]:
            add(2, f"outdated ATT&CK ID {', '.join(r['retagged'])} (MITRE replaced it)")
        if r["duplicate"]:
            add(2, "another rule has the same name")
        if not r["eventtypes"] and not r["logtypes"]:
            obs = ", ".join(f"{k} ({v})" for k, v in sorted(r["observed"].items(), key=lambda kv: -kv[1])[:5])
            add(3, "not scoped by event type or log type" + (f"; triggered on {obs}" if obs else "; run rule_logtypes to see what it fires on"))
        if len(r["techniques"]) >= 3:
            # one firing makes every tagged technique "Detected": worth a look when it carries the counts
            add(2 if r["state"] == "firing" else 3,
                f"tagged with {len(r['techniques'])} techniques ({', '.join(r['techniques'][:6])}): one firing counts all "
                "of them as detected - keep only the tags it really detects")
        lab = sorted(lab_hits.get(r["name"], set()) - set(r["techniques"]))
        if lab:
            add(3, f"fired in Atomic Red Team tests for {', '.join(lab)} but isn't tagged with it - add the tag if that's intended")
        if r["state"] in ("not in export", "no export"):
            add(3, "no evidence (not in rule health export)")
        if r["imported"]:
            add(3, "imported from files - enabled state unknown")
        rr = rob_rules.get(r["name"], {})
        if rr.get("robustness") == "1":
            add(3, "easy to evade (MITRE robustness 1)" + (f": keys on {rr['weakest_fields']}" if rr.get("weakest_fields") else ""))
        if reasons:
            out.append({"rule": r["name"], "priority": {1: "high", 2: "medium", 3: "low"}[prio],
                        "reasons": "; ".join(reasons), "techniques": ", ".join(r["techniques"]),
                        "last_fired": r["last"] or "", "detections": "" if r["count"] is None else r["count"],
                        "not_malicious_pct": "" if r["fp_pct"] is None else r["fp_pct"],
                        "event_types": ", ".join(sorted(r["eventtypes"])), "log_types_named": ", ".join(sorted(r["logtypes"])),
                        "log_types_observed": ", ".join(sorted(r["observed"]))})
    out.sort(key=lambda x: (["high", "medium", "low"].index(x["priority"]), x["rule"]))
    return out


def cmd_review(args):
    """yadda review <environment>  - rules that need individual evaluation -> rule_review.csv (keeps your decisions)."""
    if not args:
        die("usage: yadda review <environment>")
    c = envdir(args[0])
    inv = inputs.current(c, "inventory")
    inventory = _read_inventory(inv) if inv else []
    rows = _review(c, _rule_facts(c), inventory)
    f = c / "rule_review.csv"
    keep, previous = {}, {}
    if f.exists():
        head, old = read_csv(f)
        if "rule" not in head:
            die(f"{f.name}: no 'rule' column - was it re-saved in another format? Fix or delete it, then run again")
        previous = {r["rule"]: {k: v for k, v in r.items() if k} for r in old}   # incl. columns you added
        for r in old:
            if any((r.get(k) or "").strip() for k in ("decision", "notes", "reviewed_on")):
                keep[r["rule"]] = r
    fields = ["rule", "priority", "reasons", "decision", "notes", "reviewed_on", "techniques", "last_fired",
              "detections", "not_malicious_pct", "event_types", "log_types_named", "log_types_observed"]
    out = [{**previous.get(r["rule"], {}), **r,
            **{k: keep.get(r["rule"], {}).get(k, "") for k in ("decision", "notes", "reviewed_on")}} for r in rows]
    listed = {r["rule"] for r in rows}
    for name, r in sorted(keep.items()):     # no longer flagged, but a person wrote something: keep it
        if name not in listed:
            out.append({**r, "priority": "resolved", "reasons": "no longer flagged (kept because it has your notes)"})
    write_csv(f, fields, out)
    pc = Counter(r["priority"] for r in rows)
    print(f"{c.name}: {len(rows)} rules to review - high {pc['high']}, medium {pc['medium']}, low {pc['low']}"
          f"  ({sum(1 for r in rows if keep.get(r['rule'], {}).get('decision'))} already have a decision)")
    for r in [r for r in rows if r["priority"] == "high"][:15]:
        print(f"  HIGH  {r['rule']}: {r['reasons']}")
    print(f"worklist: {f}  (fill in decision / notes / reviewed_on; they are kept on the next run)")


def technique_support(facts: dict) -> dict:
    """What each technique's detection rests on: {technique: [{'rule', 'tags', 'state', 'noisy'}]} - so a Detected
    technique carried by one rule tagged with six techniques can be told apart from one with its own rules."""
    out = defaultdict(list)
    for r in facts["rules"]:
        for t in r["techniques"]:
            out[t].append({"rule": r["name"], "tags": len(r["techniques"]), "state": r["state"], "noisy": r["noisy"]})
    for t in out:
        out[t].sort(key=lambda x: (x["state"] != "firing", x["tags"], x["rule"]))
    return out


def _rule_dcs(text: str, mapping: list[dict]) -> set:
    """ATT&CK data components a rule's events: section can see, from its event type / log type / product event
    filters. A rule with none of those filters returns an empty set (its data paths can't be read from the text)."""
    sc = scope(text)        # live (not commented out, not negated) filters, from the YARA-L tree parser
    ets, lts, pets = sc["event_types"], sc["log_types"], sc["product_event_types"]
    if not (ets or lts or pets):
        return set()
    dcs = set()
    for et in ets or {""}:
        for lt in lts or {""}:
            for pet in pets or {""}:
                dcs |= _row_dcs({"event_type": et, "log_type": lt, "product_event_type": pet}, mapping)
    return dcs


def _depth(facts: dict, in_scope: dict, state_rows: dict) -> dict:
    """Per technique: the inputs of its MITRE detection routes (one per platform in scope) that the enabled rules
    tagged with it read. Depth = the best route's share: a rule set that fully reads the Windows route is deep for
    Windows even if the Office Suite route is untouched (that one shows in the route's own gaps)."""
    by_tech = defaultdict(list)
    for r in facts["rules"]:
        for t in r["techniques"]:
            by_tech[t].append(r)
    from delib.routes import log_type_platforms
    from delib.routes import rule_platforms as _rp
    table = log_type_platforms()

    def rule_platforms(r):          # from the log types a rule names; none named = it could be any platform
        return _rp({"logtypes": r.get("logtypes")}, table)
    out = {}
    for tid in in_scope:
        rules = by_tech.get(tid, [])
        unscoped = [r["name"] for r in rules if not r["dcs"]]
        readable = [r for r in rules if r["dcs"]]
        best, best_ratio, read = None, -1.0, set()
        for rt in (state_rows.get(tid) or {}).get("routes", []):
            need = {i["dc"] for i in rt["inputs"] if i["measurable"]}
            on = [r for r in rules if rule_platforms(r) is None or rt["platform"] in rule_platforms(r)]
            got = set().union(*(r["dcs"] for r in on)) if on else set()
            if need:
                ratio = len(got & need) / len(need)
                if ratio > best_ratio:
                    best, best_ratio, read = (rt["platform"], need), ratio, got
        need = best[1] if best else set()
        # No rules, or none whose data paths can be read from the rule text -> depth unknown, not zero.
        paths = best_ratio if (best and readable) else None
        out[tid] = {"need": need, "read": read & need, "missing": need - read, "rules": [r["name"] for r in rules],
                    "unscoped": unscoped, "paths": paths, "platform": best[0] if best else ""}
    return out


def _tech_depth(t: str, depth: dict, art: dict, rob: dict) -> tuple:
    """(ratio or None, source). Order of evidence: Atomic Red Team once 3+ variants are tested, then MITRE's
    implementation coverage (yadda robustness), then the share of required ATT&CK data paths the rules read."""
    a = art[t]
    tested = a["fired"] + a["missed"]
    if tested >= 3:
        return a["fired"] / tested, "ART"
    r = rob.get(t)
    if r and r["impl"] is not None:
        return r["impl"], "MITRE implementations"
    p = depth.get(t, {}).get("paths")
    return (p, "data paths") if p is not None else (None, "")


# ---------------------------------------------------------------- funnel + rule ranking (shared by CLI and dashboard)
@per_environment()
def _analysis(c: Path) -> dict:
    """Everything the metrics, rules and dashboard views need, computed once."""
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    days = thresholds(c)["days"]
    ti = tech_index()
    scope_plats = _scope(c)
    in_scope = {tid: t for tid, t in ti["techs"].items() if t["platforms"] & scope_plats}
    mapping = _mapping()
    facts = _rule_facts(c)
    for r in facts["rules"]:
        f = c / "rules" / f"{r['name']}.yaral"
        r["dcs"] = _rule_dcs(f.read_text(encoding="utf-8") if f.exists() else "", mapping)
    st = {r["id"]: r for r in _states(c, in_scope, scope_plats)[0]}
    depth = _depth(facts, in_scope, st)
    art = _art_depth(c)
    n_all = len(ti["techs"])
    ceiling = len(in_scope)
    # Nested stages: telemetry >= enabled rule >= working >= validated. A technique counts as "with an enabled
    # rule" only if an enabled, tagged SIEM rule covers it - a score typed by hand (e.g. an EDR-only detection)
    # shows on the dashboard but isn't counted here.
    ruled_set = {t for r in facts["rules"] for t in r["techniques"]} & set(in_scope)
    # One definition everywhere: Validated = score 4-5 (the technique state). An Atomic variant that fired is shown
    # separately - one variant proves some of the technique, not all of it; yadda score records 4 once tests are enough.
    validated_set = {t for t in ruled_set if st[t]["score"] >= 4}
    art_fired_only = sorted(t for t in ruled_set - validated_set if art[t]["fired"] > 0)
    working = sorted(t for t in ruled_set if st[t]["score"] >= DETECTED)
    ruled = len(ruled_set)
    telemetry = sum(1 for t, v in st.items() if v["vis"] >= 2 or t in ruled_set)
    some_inputs = sum(1 for t, v in st.items() if v["vis"] == 1 and t not in ruled_set)
    one_short = sum(1 for t, v in st.items() if v.get("one_short") and t not in ruled_set)
    manual_only = sorted(t for t, v in st.items() if v["score"] >= 1 and t not in ruled_set)
    rob = _robustness(c)

    def tech_depth(t):          # ART (3+ variants tested), else MITRE implementations, else data paths, else None
        return _tech_depth(t, depth, art, rob)[0]
    known = [tech_depth(t) for t in working if tech_depth(t) is not None]
    unknown_depth = len(working) - len(known)
    depth_low, depth_high = round(sum(known), 1), round(sum(known) + unknown_depth, 1)
    validated = len(validated_set)
    tested_t = [t for t in in_scope if art[t]["fired"] + art[t]["missed"] > 0]
    variant_rate = (sum(art[t]["fired"] for t in tested_t) / sum(art[t]["fired"] + art[t]["missed"] for t in tested_t)) if tested_t else None
    funnel = [("ATT&CK techniques (all platforms)", n_all, "the Enterprise matrix, sub-techniques included", None),
              ("In scope for this environment", ceiling, "on the environment's platforms; every % below is of this number", None),
              ("Telemetry ceiling", telemetry, "every input of a MITRE detection route is in the SIEM, or a rule exists"
               f"; {some_inputs} more have some inputs, {one_short} of them one input short", None),
              ("With an enabled rule", ruled, "at least one enabled SIEM rule tagged with the technique"
               + (f"; {len(manual_only)} technique{' scored by hand without a rule is' if len(manual_only) == 1 else 's scored by hand without a rule are'} not counted" if manual_only else ""), None),
              ("Working detection", len(working), "a rule fired recently and isn't noisy, or a test proved it (score 3+). "
               "A firing rule detects something; it doesn't show that every variant is caught", None),
              ("Depth-weighted working", depth_low, "working techniques weighted by how much of them the rules cover "
               "(Atomic tests once 3+ variants are tested, else MITRE implementations, else data paths)"
               + (f"; {unknown_depth} of unknown depth counted as 0, up to {depth_high} if they are complete" if unknown_depth else ""),
               depth_high if unknown_depth else None),
              ("Validated", validated, "proven by a test (score 4-5)"
               + (f"; {len(art_fired_only)} more {'has' if len(art_fired_only) == 1 else 'have'} an Atomic variant that fired but no score 4 yet (record it with yadda score)"
                  if art_fired_only else ""), None)]
    # rule ranking (enabled rules only - _rule_facts reads enabled, non-archived rules)
    rules = facts["rules"]
    tech_rules = defaultdict(list)
    for r in rules:
        for t in r["techniques"]:
            tech_rules[t].append(r)
    prev = {tid: t["prevalence"] for tid, t in ti["techs"].items()}
    counts = sorted(r["count"] for r in rules if r["count"])
    p90 = counts[int(len(counts) * .9)] if len(counts) >= 10 else None
    ranked = []
    for r in rules:
        sole = [t for t in r["techniques"] if len(tech_rules[t]) == 1]
        uniq_paths = set()
        for t in r["techniques"]:
            others = set().union(*(o["dcs"] for o in tech_rules[t] if o is not r))
            uniq_paths |= (r["dcs"] & depth.get(t, {}).get("need", set())) - others
        tune = []
        if r["noisy"]:
            tune.append(f"noisy: {r['fp_pct']}% of {r['cases']} closed cases not malicious")
        elif r["fp_pct"] is not None and r["cases"] >= 5 and r["fp_pct"] > 25:
            tune.append(f"some noise: {r['fp_pct']}% of {r['cases']} cases not malicious")
        if p90 and r["count"] and r["count"] >= p90 and not r["malicious"]:
            tune.append(f"top-10% volume ({r['count']:,} detections), 0 of {r['cases']} closed cases malicious"
                        if r["cases"] else f"top-10% volume ({r['count']:,} detections) and no closed cases to show it finds anything real")
        broken = r["state"] == "never fired"
        ranked.append({**r, "sole": sole, "uniq_paths": sorted(uniq_paths),
                       "prevalence": sum(prev.get(t, 0) for t in r["techniques"]), "tune": tune, "broken": broken,
                       "working": r["state"] == "firing" and not r["noisy"]})
    useful = sorted([x for x in ranked if x["techniques"]],
                    key=lambda x: (-x["working"], -len(x["sole"]), -x["malicious"], -len(x["uniq_paths"]), -x["prevalence"], x["name"]))
    tuning = sorted([x for x in ranked if x["tune"]], key=lambda x: (-(x["cases"] - x["malicious"]), -(x["count"] or 0)))
    rrules = _robustness_rules(c)
    for x in ranked:
        rr = rrules.get(x["name"], {})
        x["robustness"] = int(rr["robustness"]) if rr.get("robustness") else None
        x["robustness_status"] = rr.get("status", "not run" if not rrules else "not translated")
    # One definition of the headline numbers, shared by every output: SIEM-rule detections are the funnel;
    # techniques scored by hand without a SIEM rule (e.g. proven on an EDR) are reported next to them, never mixed in.
    hand = sorted(t for t in manual_only if st[t]["score"] >= 3)
    counts = {"detected_by_rules": len(working), "validated_by_rules": len(validated_set),
              "scored_by_hand": len(hand), "hand_validated": sum(1 for t in hand if st[t]["score"] >= 4),
              "one_short": one_short}
    # Security products in the SIEM that labelled what they saw with an ATT&CK id: a separate measure, never mixed
    # into the funnel (it says a product detected the technique here, not that a SIEM rule covers it).
    product = {t: lts for t, lts in inputs.product_alerts(c).items() if t in in_scope}
    counts.update({"product_detected": len(product), "product_only": len(set(product) - set(working)),
                   "product_export": inputs.current(c, "product_alerts") is not None})
    return {"counts": counts, "product": product, "rob": rob, "env": env, "ruled": sorted(ruled_set), "manual_only": manual_only, "days": days, "in_scope": in_scope, "scope_plats": scope_plats, "facts": facts, "depth": depth,
            "art": art, "funnel": funnel, "ceiling": ceiling, "telemetry": telemetry, "working": working,
            "variant_rate": variant_rate, "tested_techniques": len(tested_t), "useful": useful, "tuning": tuning,
            "ranked": ranked}


def cmd_metrics(args):
    """yadda metrics <environment>  - coverage funnel as % of the ATT&CK ceiling, depth and validation numbers"""
    if not args:
        die("usage: yadda metrics <environment>")
    c = envdir(args[0])
    a = _analysis(c)
    ceil = a["ceiling"]
    print(f"{c.name}: coverage funnel (platforms: {', '.join(sorted(a['scope_plats']))})\n")
    for label, n, why, hi in a["funnel"]:
        shown = f"{n}-{hi}" if hi is not None else str(n)
        pc = "" if label.startswith("ATT&CK techniques") else (
            f"{_pct(n, ceil)}-{_pct(hi, ceil)}" if hi is not None else f"{_pct(n, ceil):>7}") + " of scope"
        print(f"  {label:32} {shown:>9}  {pc:22}  {why}")
    w = len(a["working"])
    print(f"\n  Working detection as % of the telemetry ceiling: {_pct(w, a['telemetry'])}"
          f"  (how much of what is detectable today is detected)")
    dd = [_tech_depth(t, a["depth"], a["art"], a["rob"]) for t in a["working"]]
    deep = sum(1 for r, _ in dd if (r or 0) >= .67)
    src = Counter(sname for r, sname in dd if r is not None)
    print(f"  Working techniques with deep coverage (67%+): {deep} of {w}  (by: " + (", ".join(f"{k} {v}" for k, v in src.items()) or "-") + ")")
    if a["rob"]:
        rb = Counter(a["rob"].get(t, {}).get("robustness") for t in a["working"])
        print(f"  Robustness of working techniques (MITRE, best rule, 1-5): 3+: {sum(v for k, v in rb.items() if k and k >= 3)}, "
              f"1-2: {sum(v for k, v in rb.items() if k and k < 3)}, not scorable: {rb[None]}")
    else:
        print("  Robustness: not measured yet - yadda robustness <environment>")
    if a["variant_rate"] is not None:
        print(f"  ART variants: {a['variant_rate'] * 100:.0f}% of tested variants fired, across {a['tested_techniques']} techniques")
    else:
        print("  ART variants: nothing tested yet - yadda atomics <environment> lists what to run")
    c = envdir(args[0])
    tp = _threat_priorities(c, _states(c, a["in_scope"], a["scope_plats"])[0], a["in_scope"], a["scope_plats"])
    if tp["n"]:
        p1 = tp["tiers"]["P1"]
        print(f"  Threats ({tp['n']} in THREATS=): {tp['covered']} of {len(tp['rows'])} techniques detected ({_pct(tp['covered'], len(tp['rows']))}), "
              f"{tp['weighted'] * 100:.1f}% weighted by group use, P1 {p1['validated'] + p1['detected']}/{sum(p1.values())} - details: yadda priorities {c.name}")
    else:
        print("  Threats: none set - yadda actors ... --environment <environment> --set")


def cmd_rules(args):
    """yadda rules <environment> [N]  - most useful enabled rules and the ones that need tuning -> rule_ranking.csv"""
    if not args:
        die("usage: yadda rules <environment> [how many to show, default 15]")
    c, n = envdir(args[0]), int(args[1]) if len(args) > 1 else 15
    a = _analysis(c)
    print(f"{c.name}: {len(a['ranked'])} enabled rules\n\nMOST USEFUL  (working first, then: only rule for a technique, "
          f"confirmed true positives, data paths no other rule reads, attacker prevalence)")
    print(f"  {'rule':52} {'state':12} {'sole':>4} {'TP':>4} {'uniq paths':>10} {'prev':>5} {'robust':>6}  techniques")
    for r in a["useful"][:n]:
        print(f"  {r['name'][:52]:52} {r['state']:12} {len(r['sole']):>4} {r['malicious']:>4} {len(r['uniq_paths']):>10} "
              f"{r['prevalence']:>5} {r['robustness'] or '-':>6}  {', '.join(r['techniques'][:5])}")
    weak = [r for r in a["ranked"] if r["robustness"] == 1 and r["working"]]
    if weak:
        print(f"\nEASY TO EVADE  ({len(weak)} working rules score robustness 1 in MITRE's calculator: they key on values an "
              f"attacker controls - file names, paths, IPs, hashes)")
        for r in weak[:n]:
            print(f"  {r['name']}")
    print(f"\nNEEDS TUNING  ({len(a['tuning'])} rules)")
    for r in a["tuning"][:n]:
        print(f"  {r['name'][:52]:52} {'; '.join(r['tune'])}")
    broken = [r for r in a["ranked"] if r["broken"]]
    print(f"\nNEVER FIRED  ({len(broken)} rules - rare by design, or broken; see yadda review)")
    for r in broken[:n]:
        print(f"  {r['name']}")
    f = out_dir(c, "data") / "rule_ranking.csv"
    write_rows(f, ["rule", "state", "working", "sole_techniques", "true_positives", "cases", "not_malicious_pct",
                   "detections", "unique_data_paths", "prevalence", "techniques", "tuning", "robustness", "robustness_status"],
               [[r["name"], r["state"], r["working"], " ".join(r["sole"]), r["malicious"], r["cases"],
                 "" if r["fp_pct"] is None else r["fp_pct"], "" if r["count"] is None else r["count"],
                 " | ".join(r["uniq_paths"]), r["prevalence"], " ".join(r["techniques"]), "; ".join(r["tune"]),
                 r["robustness"] or "", r["robustness_status"]]
                for r in a["useful"] + [x for x in a["ranked"] if not x["techniques"]]])
    print(f"\nfull table: {f}")
