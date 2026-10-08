"""dashboard - the one-page HTML dashboard (yadda dashboard), built from the environment's result files."""
from __future__ import annotations

from delib import inputs

import csv
import datetime as dt
from collections import Counter, defaultdict
from delib.config import _pct, envdir, die, out_dir, read_env, write_text
from delib.attack import attack_version, resolve, tech_index
from delib.telemetry import _read_inventory, _row_dcs
from delib.facts import _rule_facts, _states, STATES, thresholds
from delib.robustness import _robustness_rules
from delib.actors import _actors
from delib.priorities import _threat_priorities, _tier_label
from delib.analysis import _analysis, _review, _tech_depth
from delib.sigma import candidates
from delib.upstream import tool_versions


TEXT_ON = {"validated": "#fff", "detected": "#fff", "buildable": "#fff", "blind": "#fff"}   # else dark text


def _telemetry_section(platforms: list, obs: dict, esc, environment: str = "<environment>") -> str:
    """Per ATT&CK platform: log types seen in SecOps, the MITRE detection routes they support, and what's missing."""
    rows = []
    for p in platforms:
        if not p["routes"]:
            continue
        lts = sorted(p["log_types"].items(), key=lambda x: -x[1])
        seen = (", ".join(f"{esc(k)} <span class='small'>({v:,})</span>" for k, v in lts[:6]) + (" …" if len(lts) > 6 else "")
                if lts else "<b>No telemetry inventory yet</b>" if not obs.get("has_inventory")
                else "<b class='crit'>Nothing seen in SecOps</b><div class='small'>the platform may still be in use: "
                "its logs may not be forwarded, or have no parser</div>")
        tot = p["routes"] or 1
        bar = "".join(f'<span class="seg" style="width:{100 * p[k] / tot:.1f}%;background:{col}" title="{lab}: {p[k]}"></span>'
                      for k, lab, col in (("all", "all inputs seen", "#2a78d6"), ("some", "some inputs seen", "#ec835a"),
                                          ("none", "no inputs seen", "#d03b3b"), ("unseen", "platform/product not seen", "#9b7fc4"),
                                          ("unknown", "can't tell", "#d6d5cf")) if p[k])
        def item(m):
            how = (f" <span class=small>MITRE's source {esc(', '.join(m['carriers'][:2]))} is already sent: check its events or the mapping</span>"
                   if m.get("enable") and m.get("by_source") else
                   f" <span class=small>already sending {esc(', '.join(m['carriers'][:2]))}; enable {esc(', '.join(m['enable'][:3]))}</span>"
                   if m.get("enable") else f" <span class=small>onboard {esc(m['onboard'])} (MITRE's main source)"
                   + (f"; MITRE also names {esc(m['alt']['source'])}, sent as {esc(', '.join(m['alt']['log_types']))}" if m.get("alt") else "")
                   + "</span>" if m.get("onboard") else f" <span class=small>(MITRE: {esc(', '.join(m['top_sources']))})</span>" if m["top_sources"] else "")
            return (f"<li><b>{esc(m['dc'])}</b>{' (' + esc(m['product']) + ')' if m['product'] else ''} completes "
                    f"{len(m['completes'])}, helps {len(m['techniques'])}{how}</li>")
        top, rest = p["missing"][:2], p["missing"][2:8]
        miss = "".join(item(m) for m in top) + (
            f"<li class='more'><details><summary>{len(p['missing']) - 2} more</summary><ul class='tight'>"
            + "".join(item(m) for m in rest) + "</ul></details></li>" if rest else "")
        rows.append(f"<tr><td><b>{esc(p['platform'])}</b></td><td>{seen}</td>"
                    f"<td class='barcell'><div class='bar'>{bar}</div><div class='small'>{p['all']} all inputs · "
                    f"{p['some']} some · {p['none']} none · {p['unseen']} platform/product not seen · {p['unknown']} can't tell (of {p['routes']})</div></td>"
                    f"<td><ul class='tight'>{miss or '<li>nothing missing</li>'}</ul></td></tr>")
    from delib.routes import telemetry_notes
    title = {"place": "Needs placing", "alerts": "Alert feeds", "none": "No ATT&amp;CK platform", "idp": "Identity",
             "os": "Host OS"}
    notes = telemetry_notes(obs, platforms, environment)
    note = ("<ul class='notes'>" + "".join(f"<li><b>{title[k]}:</b> {esc(t)}</li>" for k, t in notes) + "</ul>") if notes else ""
    if not obs.get("has_inventory"):
        note += "<p class='why'><b>No telemetry inventory yet.</b> Put the export in the environment's inputs folder. Until then every platform shows as not seen.</p>"
    return f"""<h2>Telemetry seen</h2><p class="why">Log types in SecOps per ATT&amp;CK platform, and how many MITRE detection routes (one analytic per technique and platform) they support. A log type counts only for its own platform. "Nothing seen" means no logs from that platform reach the SIEM, not that the platform isn't there.</p>
<div class="wrap"><table><thead><tr><th>Platform</th><th>Log types seen (events)</th><th>MITRE detection routes</th><th>Missing inputs (biggest gain first)</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>{note}"""


def _matrix_section(rows: list, ti: dict, scope_plats: set, esc, support: dict | None = None,
                    product: dict | None = None) -> str:
    """The ATT&CK Enterprise matrix for the platforms in scope, each technique coloured by its state, with the
    number detected per tactic; hover shows what each detection rests on."""
    support, product = support or {}, product or {}
    colour = {k: col for k, _, col, _ in STATES}
    label = {k: lbl for k, lbl, _, _ in STATES}
    by_id = {r["id"]: r for r in rows}
    cols = []
    for tac in ti["tactic_order"]:
        parents = sorted({r["id"].split(".")[0] for r in rows if tac in r["tactics"]})
        cells = []
        for pid in parents:
            subs = [r for r in rows if r["id"].startswith(pid + ".") and tac in r["tactics"]]
            own = by_id.get(pid)
            st = own["state"] if own else min((s["state"] for s in subs), key=lambda k: [x[0] for x in STATES].index(k))
            name = (own or {}).get("name") or ti["techs"].get(pid, {}).get("name", pid)
            sub_bar = "".join(f'<i style="background:{colour[s["state"]]}" title="{esc(s["id"])} {esc(s["name"])}: {esc(label[s["state"]])}"></i>'
                              for s in sorted(subs, key=lambda s: s["id"]))
            ids = [pid] + [x["id"] for x in subs]
            rests = [f"{x['rule']} ({x['tags']} techniques)" for i in ids for x in support.get(i, []) if x["tags"] >= 3]
            prod = sorted({lt for i in ids for lt in product.get(i, {})})
            on = sorted((own or {}).get("detected_on") or [])
            tip = (f"{pid} {name}: {label[st]}" + (f" ({len(subs)} sub-techniques below)" if subs else "")
                   + (f". Detected on: {', '.join(on)}" if on and "*" not in on and st in ("validated", "detected") else "")
                   + (f". Rests on broadly tagged rules: {', '.join(sorted(set(rests)))}" if rests else "")
                   + (f". Security product detections (not counted): {', '.join(prod)}" if prod else ""))
            cells.append(f'<div class="cell{" pd" if prod else ""}{" wide" if rests else ""}" style="background:{colour[st]};color:{TEXT_ON.get(st, "#111")}" title="{esc(tip)}">'
                         f'<b>{esc(pid)}</b> {esc(name)}{f"<div class=subs>{sub_bar}</div>" if subs else ""}</div>')
        if cells:
            tac_rows = [r for r in rows if tac in r["tactics"]]
            det = sum(1 for r in tac_rows if r["state"] in ("validated", "detected"))
            data = sum(1 for r in tac_rows if r["state"] == "buildable")
            cols.append(f'<div class="col"><div class="tac">{esc(tac.replace("-", " ").title())}'
                        f'<div class="tc" title="techniques incl. sub-techniques: detected / data, no rule / in scope">'
                        f'<b>{det}</b> det · {data} data · {len(tac_rows)}</div></div>{"".join(cells)}</div>')
    legend = "".join(f'<span class="lg"><i style="background:{col}"></i>{esc(lab)}</span>' for _, lab, col, _ in STATES)
    legend += ('<span class="lg"><i class="pdk"></i>detected by a security product (not counted)</span>'
               '<span class="lg"><i class="widek"></i>rests on a rule tagged with 3+ techniques</span>')
    return f"""<h2>ATT&amp;CK Enterprise matrix</h2><p class="why">ATT&amp;CK Enterprise v{esc(attack_version())} on {esc(", ".join(sorted(scope_plats)))}; ICS and Mobile are not assessed. Each cell is a technique coloured by its state, with its sub-techniques in the strip below. Under each tactic: detected, data but no rule, and in scope. A dashed outline means the detection rests on a rule tagged with 3 or more techniques, so one alert counts for all of them. The same view is in 3_navigator_layers.</p>
<div class="legend">{legend}</div><div class="matrix">{"".join(cols)}</div>"""


def _actions_section(actions: list, esc) -> str:
    if not actions:
        return ""
    rows = "".join(f"<tr><td class='d'>{esc(a['kind'][2:])}</td><td><b>{esc(a['action'])}</b><div class='small'>{esc(a['why'])}</div></td>"
                   f"<td class='n'>{a['unlocks']}</td><td class='n'>{a['threat_used'] if a['threat_used'] != '' else '-'}</td>"
                   f"<td class='small'>{esc(a['how'])}</td></tr>" for a in actions)
    return f"""<h2>Next actions</h2><p class="why">Grouped by kind, most useful first: telemetry that completes the most MITRE routes, rules that can't fire or are noisy, rules to write, detections to test. "Used by threats": how many of the action's techniques the environment's threat groups use.</p>
<div class="scroll"><table><thead><tr><th>Kind</th><th>Action</th><th class="n">Techniques</th><th class="n" title="how many of those techniques the environment's threat groups use">Used by threats</th><th>How</th></tr></thead><tbody>{rows}</tbody></table></div>"""


TABS = [("overview", "Overview"), ("actions", "Next actions"), ("telemetry", "Telemetry"), ("attack", "ATT&amp;CK"),
        ("threats", "Threats"), ("rules", "Rules")]


def previous_funnel(c) -> tuple[str, dict]:
    """(date, {stage: value}) from the newest earlier dated output folder that has a funnel; ('', {}) if none."""
    import re as _re
    base = out_dir(c).parent
    today = str(dt.date.today())
    for d in sorted((x for x in base.iterdir() if x.is_dir() and _re.fullmatch(r"\d{4}-\d{2}-\d{2}", x.name)
                     and x.name < today), reverse=True):
        f = d / "data" / "funnel.csv"
        if f.exists():
            with f.open(encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
            vals = {}
            for r in rows:
                try:
                    vals[r["stage"]] = float(r["techniques"])
                except (KeyError, ValueError):
                    pass
            return d.name, vals
    return "", {}


RANK_OF = {k: i for i, (k, _, _, _) in enumerate(STATES)}
CRANK = {k: i for i, k in enumerate(["validated", "detected", "elsewhere"] + [k for k, *_ in STATES[2:]])}


def _strip(states: list, esc) -> str:
    """A row of small squares, one per item, coloured by state: [(state, title)]."""
    from delib.facts import CONTEXT_STATES
    colour = {k: col for k, _, col, _ in CONTEXT_STATES}
    colour["out of scope"] = "transparent"
    return "<div class='strip'>" + "".join(
        f'<i style="background:{colour.get(st, "#ccc")}" title="{esc(t)}"></i>' for st, t in states) + "</div>"


def _context_section(tc: dict, rows: list, esc, assessed: bool) -> str:
    """The environment's threats as tools and campaigns (ATT&CK), published intrusions as ordered steps (Attack Flow)
    and techniques they probably also use (TIE, inferred)."""
    if not assessed:
        return ""
    from delib.facts import CONTEXT_STATES
    label = {k: lbl for k, lbl, _, _ in CONTEXT_STATES}
    names = {r["id"]: r["name"] for r in rows}
    out = ['<div class="legend">' + "".join(f'<span class="lg"><i style="background:{col}"></i>{esc(lab)}</span>'
                                            for _, lab, col, _ in CONTEXT_STATES) + "</div>"
           '<p class="why">Here a technique counts as detected only on the platform where the tool or step runs. A rule '
           'on cloud audit logs does not see the same technique on a Windows host, so that step shows as "Detected, '
           'not on this platform". Tools run on the platforms ATT&amp;CK lists for them; intrusion steps are placed on '
           'hosts when the technique runs on hosts.</p>']
    sw = tc["software"][:20]
    if sw:
        body = "".join(
            f'<tr><td><b>{esc(r["name"])}</b> <span class="small">{esc(r["type"])} {esc(r["id"])}</span></td>'
            f'<td class="small">{esc(", ".join(u.split(" (")[0] for u in r["used_by"]))}</td>'
            f'<td>{_strip([(r["context"][t], t + " " + names.get(t, "") + ": " + label[r["context"][t]]) for t in sorted(r["ids"], key=lambda t: (CRANK[r["context"][t]], t))], esc)}'
            f'<div class="small">{r["detected"]} of {r["techniques"]} detected</div></td>'
            f'<td class="small">{esc(", ".join(r["gaps"][:6]))}{" …" if len(r["gaps"]) > 6 else ""}</td></tr>' for r in sw)
        camps = "".join(f"<li><b>{esc(r['name'])}</b> ({esc(', '.join(u.split(' (')[0] for u in r['used_by']))}): "
                        f"{r['detected']} of {r['techniques']} techniques detected</li>" for r in tc["campaigns"])
        out.append(f"""<h3>Tools and malware they use</h3><p class="why">The software ATT&amp;CK links to these groups, most shared first. Each technique has a procedure example (Procedures sheet in the workbook) showing what a rule should look for; one rule on how a tool behaves can cover several of its techniques. Gaps are listed closest to detected first.</p>
<div class="scroll"><table><thead><tr><th>Software</th><th>Used by</th><th>Detected</th><th>Gaps</th></tr></thead><tbody>{body}</tbody></table></div>{f"<ul>{camps}</ul>" if camps else ""}""")
    flows = tc["flows"]
    if flows:
        body = "".join(
            f'<tr><td><b>{esc(f["name"])}</b>{"<div class=small>names " + esc(", ".join(f["relevant_to"])) + "</div>" if f["relevant_to"] else ""}</td>'
            f'<td>{_strip([(s["state"], "step " + str(s["step"]) + " " + s["technique"] + " " + s["name"] + ": " + label.get(s["state"], s["state"])) for s in f["steps"]], esc)}</td>'
            f'<td class="n">{f["covered"]} of {f["judged"]}</td>'
            f'<td class="n">{("step " + str(f["first_seen_step"]) + " of " + str(f["total_steps"])) if f["first_seen_step"] else "never"}</td></tr>'
            for f in flows)
        out.append(f"""<h3>Real intrusions, step by step</h3><p class="why">Published intrusions from MITRE CTID's Attack Flow corpus: one square per action, in order, coloured by this environment's state (blank: not on its platforms). The earlier the first detected step, the sooner a rule would fire. Flows that name the environment's threat groups or their malware come first.</p>
<div class="scroll"><table><thead><tr><th>Flow</th><th>Steps in order</th><th class="n">Actions detected</th><th class="n">First detected at</th></tr></thead><tbody>{body}</tbody></table></div>""")
    inf = tc["inferred"]
    if inf:
        by = {}
        for r in inf:
            by.setdefault(r["threat"], []).append(r)
        body = "".join(
            f'<tr><td>{esc(t)}</td><td>' + ", ".join(
                f'<span title="{esc(names.get(r["technique"], ""))}: {esc(label.get(r["state"], r["state"]))}">'
                f'<i class="dot" style="background:{dict((k, col) for k, _, col, _ in CONTEXT_STATES).get(r["state"], "#ccc")}"></i>{esc(r["technique"])}</span>'
                for r in rs) + "</td></tr>" for t, rs in by.items())
        out.append(f"""<details><summary class="h3">Techniques they probably also use (inferred)</summary><p class="why"><b>Inferred, not counted.</b> MITRE CTID's Technique Inference Engine, trained on published threat reports, ranks the techniques most likely to appear alongside the ones ATT&amp;CK lists for each group. The dot is this environment's state.</p>
<div class="wrap"><table><thead><tr><th>Threat</th><th>Top {len(next(iter(by.values())))} inferred techniques, most likely first</th></tr></thead><tbody>{body}</tbody></table></div></details>""")
    return "".join(out)


def _delta(d: float) -> str:
    if abs(d) < 0.05:
        return "="
    return f"{'+' if d > 0 else '-'}{abs(d):g}"


def _esc(v) -> str:
    import html
    return html.escape(str(v), quote=True)


def cmd_dashboard(args):
    """yadda dashboard <environment>  - one-page HTML view: coverage, blind spots, log types, rule health."""
    if not args:
        die("usage: yadda dashboard <environment>")
    c = envdir(args[0])
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    ti = tech_index()
    techs = ti["techs"]
    plat_cfg = [p.strip() for p in env.get("PLATFORMS", "").split(",") if p.strip()]
    scope_plats = set(plat_cfg) or {p for t in techs.values() for p in t["platforms"]} - {"PRE"}
    in_scope = {tid: t for tid, t in techs.items() if t["platforms"] & scope_plats}
    th = thresholds(c)
    days = th["days"]
    noisy_def = f"over {th['fp_max']}% of {th['min_cases']}+ closed cases not malicious"

    # --- inputs
    rows, have, present_dc, mapping, measurable = _states(c, in_scope, scope_plats)
    inv = inputs.current(c, "inventory")
    inventory = _read_inventory(inv) if inv else []
    facts = _rule_facts(c)
    rules, untagged, retags, dropped = facts["rules"], facts["untagged"], facts["retags"], facts["dropped"]
    review = _review(c, facts, inventory)
    today = dt.date.today()
    an = _analysis(c)
    depth, art = an["depth"], an["art"]
    tp = _threat_priorities(c, rows, in_scope, scope_plats)

    st = Counter(r["state"] for r in rows)
    covered = st["validated"] + st["detected"]
    n = an["counts"]
    from delib.analysis import technique_support
    from delib.procedures import threat_context
    support, product = technique_support(facts), an["product"]
    tc = threat_context(c)
    context_html = _context_section(tc, rows, _esc, bool(tp.get("assessed")))

    # telemetry seen per platform (MITRE routes), the to-do list
    from delib.routes import inventory_file, observed, platform_summary
    from delib.run import next_actions
    obs = observed(inventory_file(c))
    plat_summary = platform_summary(in_scope, scope_plats, obs, measurable)
    actions = next_actions(c, {"rows": rows, "in_scope": in_scope, "platforms": plat_summary, "obs": obs,
                               "users": {r["id"]: len(r["users"]) for r in tp["rows"]}}, limit=25)
    unmeasured = Counter(i["dc"] for r in rows for rt in r.get("routes", []) for i in rt["inputs"] if not i["measurable"])
    no_dc_known = [r for r in rows if not r.get("routes")]

    # log types: what each provides, which rules use it, build-on potential
    lt = defaultdict(lambda: {"events": 0, "ets": set(), "dcs": set()})
    for r in inventory:
        lt[r["log_type"]]["events"] += r["events"]
        lt[r["log_type"]]["ets"].add(r["event_type"])
        if r["events"] >= 100 or r["product_event_type"]:
            lt[r["log_type"]]["dcs"] |= _row_dcs(r, mapping)
    have_observed = any(r["observed"] for r in rules)
    buildable = [r for r in rows if r["state"] == "buildable"]
    lt_rows = []
    for name, d in lt.items():
        dcs = d["dcs"]
        named = [r["name"] for r in rules if name in r["logtypes"]]
        via_et = [r["name"] for r in rules if not r["logtypes"] and r["eventtypes"] & d["ets"]]
        triggered = [r["name"] for r in rules if name in r["observed"]]
        placed = obs["log_types"].get(name, {}).get("platforms") or set()
        potential = [r for r in buildable if r["need"] & dcs] if placed - {"alerts"} else []   # counts for no route
        lt_rows.append({"name": name, "events": d["events"], "ets": d["ets"], "dcs": dcs, "named": named,
                        "via_et": via_et, "triggered": triggered, "potential": potential,
                        "status": "triggered rules" if triggered else "named by rules" if named
                        else "event types used by rules" if via_et else "no ATT&CK mapping" if not dcs else "unused"})
    lt_rows.sort(key=lambda r: (["unused", "no ATT&CK mapping", "event types used by rules", "named by rules",
                                 "triggered rules"].index(r["status"]), -len(r["potential"]), -r["events"]))
    lt_status = Counter(r["status"] for r in lt_rows)

    # threat coverage: configured threats + prevalent techniques
    threat_rows = []
    for item in [x.strip() for x in env.get("THREATS", "").split(",") if x.strip()]:
        tids, labels = resolve([item])
        ts = [r for r in rows if r["id"] in set(tids)]
        if ts:
            from delib.procedures import context_state, step_platforms
            sc = Counter(context_state(r, step_platforms(r["id"])) for r in ts)    # judged where the group would act
            threat_rows.append((labels[0], len(ts), sc))
    prevalent = [r for r in rows if r["prev"] >= 10]
    psc = Counter(r["state"] for r in prevalent)
    threat_rows.append(("Prevalent techniques (used by 10+ ATT&CK groups/campaigns)", len(prevalent), psc))

    # rule metrics
    rs = Counter(r["state"] for r in rules)
    noisy = [r for r in rules if r["noisy"]]
    tech_rule_count = Counter(t for r in rules for t in r["techniques"])
    single = sum(1 for r in rows if r["state"] in ("validated", "detected") and tech_rule_count.get(r["id"], 0) == 1)


    def mtime(p):
        return dt.date.fromtimestamp(p.stat().st_mtime).isoformat() if p and p.exists() else "missing"

    # ----------------------------------------------------------------- HTML
    def bar(counter, total):
        segs = []
        from delib.facts import CONTEXT_STATES
        for key, label, color, _ in CONTEXT_STATES:
            n = counter.get(key, 0)
            if n:
                segs.append(f'<span class="seg" style="width:{100 * n / total:.2f}%;background:{color}" '
                            f'title="{_esc(label)}: {n}"></span>')
        return f'<div class="bar">{"".join(segs)}</div>'

    def pct(n, d):
        return f"{100 * n / d:.0f}%" if d else "-"

    def tile(value, label, sub="", tone=""):
        return (f'<div class="tile {tone}"><div class="v">{_esc(value)}</div><div class="l">{_esc(label)}</div>'
                f'<div class="s">{_esc(sub)}</div></div>')

    threat_html = "".join(
        f'<tr><td>{_esc(lab)}</td><td class="barcell">{bar(sc, n)}</td><td class="n">{n}</td>'
        f'<td class="n">{pct(sc["validated"] + sc["detected"], n)}</td><td class="n">{sc["buildable"]}</td>'
        f'<td class="n">{sc["thin"]}</td><td class="n">{sc["blind"]}</td><td class="n">{sc["unseen"]}</td></tr>' for lab, n, sc in threat_rows)
    from delib.facts import CONTEXT_STATES
    label_of = dict((k, l.split(" (")[0]) for k, l, _, _ in CONTEXT_STATES)
    if tp["n"]:
        try:
            groups = _actors()["groups"]
        except Exception:
            groups = {}
        prof = {}
        for label, gid, _ in tp["threats"]:
            g = groups.get(gid, {})
            prof[label] = (g.get("origin", ""), g.get("last_seen", ""),
                           ", ".join(sorted(g.get("sectors", {}))[:4]))
        threat_html = "".join(
            f'<tr><td>{_esc(lab)}</td><td class="small">{_esc(prof.get(lab, ("",))[0])}</td><td class="small d">{_esc(prof.get(lab, ("", ""))[1] or "-")}</td>'
            f'<td class="barcell">{bar(sc, n)}</td><td class="n">{n}</td>'
            f'<td class="n">{pct(sc["validated"] + sc["detected"], n)}</td><td class="n">{sc["buildable"]}</td>'
            f'<td class="n">{sc["thin"]}</td><td class="n">{sc["blind"]}</td><td class="n">{sc["unseen"]}</td></tr>' for lab, n, sc in threat_rows)
        if not tp["assessed"]:
            threat_html = "".join(
                f'<tr><td>{_esc(lab)}</td><td class="small">{_esc(prof.get(lab, ("",))[0])}</td><td class="small d">{_esc(prof.get(lab, ("", ""))[1] or "-")}</td>'
                f'<td class="small">{_esc(prof.get(lab, ("", "", ""))[2])}</td><td class="n">{n}</td></tr>' for lab, n, sc in threat_rows[:-1])
        tier_html = "".join(
            f'<tr><td class="d">{_esc(_tier_label(tp, k))}</td><td class="barcell">{bar(v, sum(v.values()) or 1)}</td><td class="n">{sum(v.values())}</td>'
            f'<td class="n">{v["validated"] + v["detected"]} ({pct(v["validated"] + v["detected"], sum(v.values()))})</td>'
            f'<td class="n">{v["elsewhere"]}</td><td class="n">{v["limited"] + v["unverified"] + v["hand"]}</td><td class="n">{v["buildable"]}</td><td class="n">{v["thin"]}</td>'
            f'<td class="n">{v["blind"]}</td><td class="n">{v["unseen"]}</td><td class="n">{v["unknown"]}</td></tr>'
            for k, v in tp["tiers"].items() if sum(v.values()))
        prio_html = "".join(
            f'<tr><td class="n">{r["rank"]}</td><td>{r["tier"]}</td><td>{_esc(r["id"])}</td><td>{_esc(r["name"])}</td>'
            f'<td class="n" title="{_esc(", ".join(r["users"]))}">{len(r["users"])}/{tp["n"]}</td>'
            + (f'<td class="d"><i class="dot" style="background:{dict((k, col) for k, _, col, _ in CONTEXT_STATES)[r["state"]]}"></i>{_esc(label_of[r["state"]])}</td>'
               if tp["assessed"] else '<td class="d">not assessed</td>')
            + f'<td class="small">{_esc(r["action"])}</td><td class="small">{_esc(", ".join(r["users"]))}</td></tr>' for r in tp["rows"])
        need_html = "".join(
            f'<tr><td><b>{_esc(d["dc"])}</b> <span class="small">{_esc(d.get("platform", ""))}</span></td><td class="n">{len(d["techs"])}</td><td class="n">{d["p1"]}</td><td class="n">{d["weight"]}</td>'
            f'<td class="small">{_esc(", ".join(d["sources"][:5]) if d["measurable"] else "no mapping yet")}</td></tr>' for d in tp["data"][:15])
        tst = tp["states"]
        tier_table = f"""<div class="wrap"><table><thead><tr><th>Priority tier</th><th>Coverage</th><th class="n">Techniques</th><th class="n">Detected</th><th class="n">Detected, not where they'd use it</th><th class="n">Limited / unverified / by hand</th><th class="n">Data, no rule</th><th class="n">Some data</th><th class="n">No data seen</th><th class="n">Platform not seen</th><th class="n">Can't tell</th></tr></thead><tbody>{tier_html}</tbody></table></div>"""
        if tp["assessed"]:
            threat_tiles = f"""<div class="tiles">
{tile(f"{tp['covered']} / {len(tp['rows'])}", "Threat techniques detected", pct(tp["covered"], len(tp["rows"])) + " of what these groups do", "good")}
{tile(f"{tp['weighted'] * 100:.0f}%", "Weighted by group use", "share of their known activity detected", "good")}
{tile(f"{tp['tiers']['P1']['validated'] + tp['tiers']['P1']['detected']} / {sum(tp['tiers']['P1'].values())}", "P1 detected", "techniques most of these groups use", "warn" if tp['tiers']['P1']['buildable'] else "")}
{tile(tst["elsewhere"], "Detected elsewhere", "only by rules on a platform they wouldn't use it on", "warn" if tst["elsewhere"] else "")}
{tile(tst["buildable"], "Data, no rule", "threat techniques you could cover today", "info")}
{tile(tst["blind"], "No data seen", "platform in the SIEM, inputs missing", "bad" if tst["blind"] else "")}
{tile(tst["unseen"], "Platform not seen", "no logs of that platform in the SIEM", "warn" if tst["unseen"] else "")}
{tile(len(tp["outside"]), "Pre-compromise", "not visible in a SIEM")}</div>"""
        else:
            threat_tiles = f"""<div class="tiles">
{tile(len(tp["rows"]), "Threat techniques", "the detection scope for this environment", "info")}
{tile(sum(tp["tiers"]["P1"].values()), "P1 techniques", f"used by {tp['p1']}+ of {tp['n']} groups", "warn")}
{tile(len(tp["data"]), "ATT&CK data types needed", "see the data table below")}
{tile(len(tp["outside"]), "Pre-compromise", "not visible in a SIEM")}</div>
<p class="why"><b>Not assessed yet:</b> no rules or telemetry loaded for this environment, so this shows the scope only. Run yadda pull and yadda data to see coverage.</p>"""
        threat_section = f"""<h2>Threat coverage</h2><p class="why">The {tp["n"]} groups in THREATS= use {len(tp["rows"])} techniques on this environment's platforms{f"; {len(tp['outside'])} more are pre-compromise and can't be seen in a SIEM" if tp["outside"] else ""}{f"; {tp['off_platform']} are on platforms the environment doesn't have" if tp["off_platform"] else ""}. P1 = used by at least {tp["p1"]} of the {tp["n"]} groups, P2 by two or more, P3 by one. "Weighted" counts a technique once per group that uses it, giving the share of these groups' known activity that would be detected.</p>
{threat_tiles}
{tier_table if tp["assessed"] else ""}
<h3>Per threat</h3><div class="wrap"><table><thead><tr><th>Threat</th><th>Origin</th><th>Last campaign</th>{'<th>Coverage</th><th class="n">Techniques</th><th class="n">Detected</th><th class="n">Data, no rule</th><th class="n">Some data</th><th class="n">No data seen</th><th class="n">Platform not seen</th>' if tp["assessed"] else '<th>Sectors targeted</th><th class="n">Techniques</th>'}</tr></thead>
<tbody>{threat_html}</tbody></table></div>
<h3>Priority list</h3><p class="why">Every technique these groups use, most-used first, with the next step. Hover the group count to see the groups.</p>
<input class="f" placeholder="Filter (e.g. P1, Data, no rule, T1059, APT41)…" data-t="prio"><div class="scroll"><table id="prio"><thead><tr><th class="n">#</th><th>Tier</th><th>ID</th><th>Technique</th><th class="n">Groups</th><th>Status</th><th>Next step</th><th>Used by</th></tr></thead><tbody>{prio_html}</tbody></table></div>
<h3>{"Missing data these threats need" if tp["assessed"] else "Data these threats need"}</h3><p class="why">ATT&amp;CK data types per platform, ranked by the group-weighted techniques they would make visible. P1 = how many of those techniques are priority 1.</p>
<div class="scroll"><table><thead><tr><th>ATT&amp;CK data type</th><th class="n">Techniques</th><th class="n">P1</th><th class="n">Weight</th><th>Provided by</th></tr></thead><tbody>{need_html}</tbody></table></div>
{context_html}"""
    else:
        threat_section = """<h2>Threat coverage</h2><p class="why">No threat groups set for this environment. Add them with <code>yadda actors --sector ... --country ... --environment ... --set</code>, or write THREATS=APT29,FIN7,redteam.yaml in environment.env.</p>"""
    cand = candidates(c)
    cand_by_t = Counter(t for row in cand for t in (row.get("covers") or "").split())
    short = [r for r in rows if r["state"] == "thin" and r.get("one_short")]
    build_html = "".join(
        f'<tr><td>{_esc(r["id"])}</td><td>{_esc(r["name"])}</td><td class="small">{_esc(", ".join(r["tactics"]))}</td>'
        f'<td class="n">{r["prev"]}</td><td>{_esc(r["route"]["platform"]) if r.get("route") else ""}</td>'
        f'<td class="n">{r["route"]["seen"]}/{r["route"]["needed"]}</td>'
        f'<td class="small">{"all seen" if r["state"] == "buildable" else "missing: " + _esc(", ".join(r.get("missing") or []))}</td>'
        f'<td class="n">{cand_by_t.get(r["id"], "")}</td></tr>'
        for r in sorted(buildable, key=lambda r: (-r["prev"], r["id"])) + sorted(short, key=lambda r: (-r["prev"], r["id"])))
    cand_note = (f' <b>Sigma candidates</b>: {len(cand)} converted SigmaHQ rules for {len(cand_by_t)} techniques are in '
                 f'<code>4_sigma_candidates</code>; they are not counted until deployed and pulled.'
                 if cand else ' Run yadda run without -sigma to get SigmaHQ rules converted for these gaps.')
    lt_html = "".join(
        f'<tr class="st-{_esc(r["status"].split()[0])}"><td><b>{_esc(r["name"])}</b></td><td>{_esc(r["status"])}</td>'
        f'<td class="n">{r["events"]:,}</td><td class="n">{len(r["triggered"]) if have_observed else "-"}</td><td class="n">{len(r["named"])}</td><td class="n">{len(r["via_et"])}</td>'
        f'<td class="n">{len(r["potential"])}</td><td class="small">{_esc(", ".join(sorted(r["dcs"])) or "-")}</td>'
        f'<td class="small">{_esc(", ".join(sorted(r["ets"])))}</td></tr>' for r in lt_rows)
    rule_html = "".join(
        f'<tr><td>{_esc(r["name"])}</td><td>{_esc(r["state"])}{" · noisy" if r["noisy"] else ""}</td>'
        f'<td class="d">{_esc(r["last"] or "")}</td><td class="n">{"" if r["count"] is None else format(r["count"], ",")}</td>'
        f'<td class="n">{"" if r["fp_pct"] is None else str(r["fp_pct"]) + "% of " + str(r["cases"])}</td>'
        f'<td class="small">{_esc(", ".join(r["techniques"]) or "UNTAGGED")}</td>'
        f'<td class="small">{_esc(", ".join(sorted(r["logtypes"])) or ", ".join(sorted(r["eventtypes"])) or "-")}</td>'
        f'<td class="small">{_esc(", ".join(sorted(r["observed"])) or "-")}</td></tr>'
        for r in sorted(rules, key=lambda r: (["firing", "fired, date unknown", "stale", "never fired", "not in export", "no export"].index(r["state"]), r["name"])))
    hyg = []
    for (old, new), rr in sorted(retags.items()):
        hyg.append(f"<li>{len(set(rr))} rules tagged <b>{_esc(old)}</b>, which MITRE replaced with <b>{_esc(new)}</b> "
                   f"(counted under {_esc(new)}; update the meta), e.g. {_esc(sorted(set(rr))[0])}</li>")
    for (tid, why), rr in sorted(dropped.items()):
        hyg.append(f"<li>{len(set(rr))} rules tagged <b>{_esc(tid)}</b>: {_esc(why)} (not counted), e.g. {_esc(sorted(set(rr))[0])}</li>")
    if untagged:
        hyg.append(f"<li>{len(untagged)} enabled rules have no usable ATT&amp;CK tag and are invisible in coverage: "
                   f"{_esc(', '.join(untagged[:15]))}{' …' if len(untagged) > 15 else ''}</li>")
    if unmeasured:
        hyg.append(f"<li>{len(unmeasured)} ATT&amp;CK data types used by MITRE's routes have no SecOps event mapping, so "
                   f"they can't be measured: {_esc(', '.join(k for k, _ in unmeasured.most_common(12)))}. Add rows to "
                   "shared/udm_event_type_to_data_component.csv.</li>")
    if no_dc_known:
        hyg.append(f"<li>{len(no_dc_known)} in-scope technique{'s have' if len(no_dc_known) != 1 else ' has'} no data requirements in ATT&amp;CK detection "
                   f"strategies, so they show as can&#39;t tell whatever the telemetry, e.g. "
                   f"{_esc(', '.join(r['id'] for r in no_dc_known[:10]))}</li>")

    ceil = an["ceiling"] or 1
    prev_date, prev = previous_funnel(c)
    from delib.run import balanced, unlocks_text
    seen_p = sum(1 for p in plat_summary if p["observed"] and p["routes"])
    all_p = sum(1 for p in plat_summary if p["routes"])
    stage = {lab: n for lab, n, _, _ in an["funnel"]}
    chg = lambda lab: (f" <span class='delta'>{_delta(float(stage[lab]) - prev[lab])} since {prev_date}</span>"
                       if prev_date and lab in prev else "")
    head_tiles = [
        (f"{n['detected_by_rules']} <small>of {len(rows)}</small>", "Detected by SIEM rules" + chg("Working detection"),
         f"{pct(n['detected_by_rules'], len(rows))} of techniques in scope; {n['validated_by_rules']} validated by test"),
        (f"{an['telemetry']} <small>({pct(an['telemetry'], len(rows))})</small>", "Telemetry ceiling" + chg("Telemetry ceiling"),
         f"every input of a MITRE route seen; {n['one_short']} more are one input short"),
        (f"{st['buildable']}", "Data, no rule", "rules you could write today"),
        (f"{seen_p} <small>of {all_p}</small>", "Platforms seen", "platforms in scope with logs in SecOps"),
    ]
    if tp["n"] and tp.get("assessed"):
        head_tiles.insert(1, (f"{tp['covered']} <small>of {len(tp['rows'])}</small>", "Threat techniques detected",
                              f"{tp['weighted'] * 100:.0f}% of these groups' known activity"))
    top = balanced(actions, 4)
    headline_html = ('<div class="head"><div class="htiles">' + "".join(
        f'<div class="ht"><div class="v">{v}</div><div class="l">{l}</div><div class="s">{_esc(sub)}</div></div>'
        for v, l, sub in head_tiles) + '</div>'
        + ('<div class="hnext"><b>Do next</b><ol>' + "".join(
            f"<li><b>{_esc(x['action'])}</b> {f"<span class='small'> ({unlocks_text(x)})</span>" if unlocks_text(x) else ""}</li>"
            for x in top) + '</ol><a href="#actions">all next actions</a></div>' if top else "") + '</div>')
    funnel_html = "".join(
        f'<tr><td><b>{_esc(lab)}</b><div class="small">{_esc(why)}</div></td>'
        f'<td class="barcell"><div class="bar"><span class="seg" style="width:{100 * float(n) / (an["funnel"][0][1] or 1):.2f}%;background:var(--accent)"></span></div></td>'
        f'<td class="n">{n if hi is None else f"{n}-{hi}"}</td>'
        f'<td class="n">{"" if i == 0 else (f"{100 * float(n) / ceil:.1f}%" if hi is None else f"{100 * float(n) / ceil:.1f}-{100 * float(hi) / ceil:.1f}%")}</td>'
        + (f'<td class="n delta">{_delta(float(n) - prev[lab]) if lab in prev else ""}</td>' if prev_date else "") + '</tr>'
        for i, (lab, n, why, hi) in enumerate(an["funnel"]))
    rob = an["rob"]

    def depth_label(t):
        ratio, src = _tech_depth(t, depth, art, rob)
        src = {"MITRE implementations": "MITRE", "data paths": "paths"}.get(src, src)
        if ratio is None:
            return "unknown", "-"
        return ("deep" if ratio >= .67 else "partial" if ratio >= .34 else "shallow"), f"{ratio * 100:.0f}% ({src})"
    depth_rows = []
    for r in sorted((r for r in rows if r["score"] >= 1), key=lambda r: (-r["score"], -r["prev"], r["id"])):
        d, a = depth.get(r["id"], {}), art[r["id"]]
        lab, val = depth_label(r["id"])
        depth_rows.append(
            f'<tr><td>{_esc(r["id"])}</td><td>{_esc(r["name"])}</td><td>{_esc(dict((k, l) for k, l, _, _ in STATES)[r["state"]])}</td>'
            f'<td class="n">{len(d.get("rules", []))}</td>'
            f'<td class="n">{len(d.get("read", ()))}/{len(d.get("need", ()))}</td>'
            f'<td class="small">{_esc(", ".join(sorted(d.get("missing", ()))) or "-")}</td>'
            f'<td class="n">{a["fired"]}/{a["fired"] + a["missed"]} of {a["available"]}</td>'
            f'<td class="n">{(str(rob[r["id"]]["matched"]) + "/" + str(rob[r["id"]]["total"])) if rob.get(r["id"]) and rob[r["id"]]["total"] else "-"}</td>'
            f'<td class="n" title="MITRE robustness of the strongest rule (1 = ephemeral value, 5 = core to the technique); precision in brackets">'
            f'{(str(rob[r["id"]]["robustness"]) + " (" + str(rob[r["id"]]["precision"]) + ")") if rob.get(r["id"]) and rob[r["id"]]["robustness"] else "-"}</td>'
            f'<td class="d"><b>{lab}</b> {val}</td></tr>')
    depth_counts = Counter(depth_label(r["id"])[0] for r in rows if r["state"] in ("validated", "detected"))
    useful_html = "".join(
        f'<tr><td>{_esc(r["name"])}</td><td>{_esc(r["state"])}</td><td class="n">{len(r["sole"])}</td><td class="n">{r["malicious"]}</td>'
        f'<td class="n">{len(r["uniq_paths"])}</td><td class="n">{r["prevalence"]}</td><td class="n">{r["robustness"] or "-"}</td><td class="small">{_esc(", ".join(r["techniques"]))}</td></tr>'
        for r in an["useful"][:20])
    tuning_html = "".join(
        f'<tr><td>{_esc(r["name"])}</td><td>{_esc("; ".join(r["tune"]))}</td><td class="n">{"" if r["count"] is None else format(r["count"], ",")}</td>'
        f'<td class="n">{r["malicious"]}</td><td class="small">{_esc(", ".join(r["techniques"]))}</td></tr>' for r in an["tuning"])

    # ---- detection quality (MITRE Detection Coverage Calculator, yadda robustness)
    rr = _robustness_rules(c)
    rk = {x["name"]: x for x in an["ranked"]}
    rf = c / "robustness_techniques.csv"
    calc_ver = next((r.get("calculator", "") for r in csv.DictReader(rf.open(encoding="utf-8-sig"))), "") if rf.exists() else ""
    calc_run = mtime(c / "robustness_rules.csv")
    if rr:
        # a robustness file may lack some columns: fill them with "" so the page still renders
        cols = ("rule", "techniques", "robustness", "precision", "weakest_fields", "status", "basis",
                "why_not_fully_scored", "fields_not_scored")
        rl = [{k: (r.get(k) or "") for k in cols} for r in rr.values()]
        stale_file = any("weakest_fields" not in r for r in rr.values())
        lvl = Counter(r["robustness"] for r in rl if r["robustness"])
        stc = Counter(r["status"] for r in rl)
        working = lambda r: rk.get(r["rule"], {}).get("working")
        easy = [r for r in rl if r["robustness"] == "1"]
        excl = [r for r in easy if r["weakest_fields"] and all("exclusion" in f for f in r["weakest_fields"].split("; "))]
        q_tiles = (tile(lvl["1"], "Robustness 1", "keys on values an attacker controls", "bad" if lvl["1"] else "")
                   + tile(lvl["2"], "Robustness 2", "core to tools the attacker brings", "warn" if lvl["2"] else "")
                   + tile(lvl["3"], "Robustness 3", "core to built-in tools", "good" if lvl["3"] else "")
                   + tile(lvl["4"] + lvl["5"], "Robustness 4-5", "core to the technique", "good" if lvl["4"] + lvl["5"] else "")
                   + tile(stc["scored (partial)"], "Partly scored", "some fields MITRE has no score for")
                   + tile(stc["not scored"], "Not scorable", "event or fields not in MITRE's dictionary")
                   + tile(stc["implementations only (not Windows)"], "Non-Windows", "implementation coverage only"))
        state_rank = {"firing": 0, "stale": 1, "never fired": 2}
        easy_html = "".join(
            f'<tr><td>{_esc(r["rule"])}</td><td>{_esc(rk.get(r["rule"], {}).get("state", "-"))}{" (working)" if working(r) else ""}</td>'
            f'<td>{_esc(r["weakest_fields"] or "-")}</td><td class="small">{_esc(r["techniques"])}</td></tr>'
            for r in sorted(easy, key=lambda r: (not working(r), r["rule"])))
        q_rows = "".join(
            f'<tr><td>{_esc(r["rule"])}</td><td>{_esc(rk.get(r["rule"], {}).get("state", "-"))}</td>'
            f'<td class="n">{r["robustness"] or "-"}</td><td class="n">{r["precision"] or "-"}</td><td>{_esc(r["status"])}</td>'
            f'<td>{_esc(r["weakest_fields"] or "-")}</td><td class="small">{_esc(r["why_not_fully_scored"] or "-")}</td>'
            f'<td class="small">{_esc(r["fields_not_scored"] or "-")}</td><td class="small">{_esc(r["basis"])}</td>'
            f'<td class="small">{_esc(r["techniques"])}</td></tr>'
            for r in sorted(rl, key=lambda r: (r["status"].startswith("implementations"), int(r["robustness"] or 9),
                                               state_rank.get(rk.get(r["rule"], {}).get("state"), 3), r["rule"])))
        quality_section = f"""<h2>Detection quality</h2><p class="why">MITRE's Detection Coverage Calculator ({_esc(calc_ver or "version unknown")}, run {calc_run}) on the {len(rl)} enabled rules. A rule's robustness is that of its weakest required field: 1 = a value the attacker controls (file name, path, IP, hash), 2 = core to a tool the attacker brings, 3 = core to a built-in tool, 4-5 = core to the technique. Exclusions count: an exclusion on an image path lets a renamed binary through. Only Windows Event Log and Sysmon fields are scored; cloud and SaaS rules get implementation coverage only.</p>
{'<p class="why"><b>The robustness results have no weakest-field column. Run yadda robustness again to fill it in.</b></p>' if stale_file else ''}
<div class="tiles">{q_tiles}</div>
<h3>Easy to evade ({len(easy)})</h3><p class="why">Rules at robustness 1 and the field that sets it.{f" For {len(excl)} of them it's an exclusion, not the match: tighten or remove the exclusion to raise the score." if excl else ""}</p>
{f'<div class="wrap"><table><thead><tr><th>Rule</th><th>State</th><th>Weakest field</th><th>Techniques</th></tr></thead><tbody>{easy_html}</tbody></table></div>' if easy else '<p class="why">None.</p>'}
<h3>All rules</h3>
<input class="f" placeholder="Filter (e.g. partial, CommandLine, T1003)…" data-t="quality"><div class="scroll"><table id="quality"><thead><tr><th>Rule</th><th>State</th><th class="n">Robustness</th><th class="n">Precision</th><th>Status</th><th>Weakest field</th><th>Why not fully scored</th><th>Fields MITRE can't score</th><th>Basis</th><th>Techniques</th></tr></thead><tbody>{q_rows}</tbody></table></div>"""
    else:
        quality_section = """<h2>Detection quality</h2><p class="why">Not measured yet. Run <code>yadda robustness """ + _esc(c.name) + """</code> (first time: <code>yadda robustness --update</code> installs MITRE's Detection Coverage Calculator).</p>"""

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_esc(c.name)} detection coverage</title>
<style>
:root{{--bg:#fcfcfb;--panel:#ffffff;--ink:#0b0b0b;--ink2:#52514e;--line:#e4e3de;--good:#0ca30c;--warn:#fab219;--crit:#d03b3b;--accent:#2a78d6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1a1a19;--panel:#232322;--ink:#fff;--ink2:#c3c2b7;--line:#3a3a37}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,sans-serif}}
main{{max-width:1300px;margin:0 auto;padding:24px 16px 64px}}h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:17px;margin:36px 0 6px}}
.meta,.small,em{{color:var(--ink2);font-size:12px;font-style:normal}}.why{{color:var(--ink2);margin:0 0 12px;max-width:900px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:14px 0}}
.group{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);margin-top:18px}}
.tile{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}}.tile .v{{font-size:24px;font-weight:650}}
.tile .l{{font-weight:600}}.tile .s{{color:var(--ink2);font-size:12px}}.tile.bad{{border-left:4px solid var(--crit)}}
.tile.warn{{border-left:4px solid var(--warn)}}.tile.good{{border-left:4px solid var(--good)}}.tile.info{{border-left:4px solid var(--accent)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--ink2);cursor:pointer;position:sticky;top:0;background:var(--panel)}}
td.n,th.n{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}.barcell{{width:38%}}
.bar{{display:flex;height:14px;border-radius:4px;overflow:hidden;gap:2px;background:var(--line)}}.seg{{display:block;height:100%}}
.legend{{display:flex;flex-wrap:wrap;gap:6px 16px;margin:8px 0}}.lg{{display:flex;align-items:center;gap:6px;font-size:13px}}
.lg i{{width:12px;height:12px;border-radius:3px;display:inline-block}}.scroll{{max-height:460px;overflow:auto;border-radius:8px}}.wrap{{overflow-x:auto;border-radius:8px}}td.d{{white-space:nowrap}}
input.f{{width:100%;max-width:360px;padding:6px 8px;margin:4px 0 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}}
h3{{font-size:15px;margin:22px 0 6px}}i.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}}tr.st-unused td:nth-child(2){{color:var(--crit);font-weight:600}}ul{{margin:6px 0;padding-left:20px}}li{{margin:3px 0;overflow-wrap:anywhere}}.meta{{overflow-wrap:anywhere}}
.sub{{font-size:14px;margin:2px 0 4px}}b.crit{{color:var(--crit)}}ul.tight{{margin:0;padding-left:16px}}
.matrix{{display:flex;gap:4px;overflow-x:auto;padding-bottom:8px;align-items:flex-start}}
.col{{flex:0 0 132px;display:flex;flex-direction:column;gap:3px}}
.tac{{font-size:11px;font-weight:650;padding:4px 2px;border-bottom:2px solid var(--ink2);min-height:38px}}.tac span{{float:right;color:var(--ink2);font-weight:400}}
.cell{{font-size:10.5px;line-height:1.25;padding:3px 4px;border-radius:3px;overflow:hidden}}.cell b{{font-weight:650}}
.subs{{display:flex;gap:1px;margin-top:2px}}.tc{{font-weight:400;color:var(--ink2);font-size:10.5px;margin-top:2px}}.tc b{{color:var(--ink)}}
.cell.pd{{box-shadow:inset -6px 6px 0 -3px #111}}.cell.wide{{outline:2px dashed var(--ink);outline-offset:-2px}}
.lg i.pdk{{background:var(--panel);box-shadow:inset -6px 6px 0 -3px #111;border:1px solid var(--line)}}.lg i.widek{{outline:2px dashed var(--ink);outline-offset:-2px;background:var(--panel)}}
.head{{display:grid;grid-template-columns:2fr 1fr;gap:12px;margin:16px 0 4px}}@media(max-width:900px){{.head{{grid-template-columns:1fr}}}}
.htiles{{align-self:start;display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}}.ht{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:10px 12px}}
.ht .v{{font-size:26px;font-weight:700}}.ht .v small{{font-size:13px;font-weight:400;color:var(--ink2)}}.ht .l{{font-weight:600}}.ht .s{{color:var(--ink2);font-size:12px}}
.hnext{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}}.hnext ol{{margin:6px 0;padding-left:20px}}
.delta{{color:var(--ink2);font-size:12px;font-weight:400}}td.delta{{font-size:13px}}a{{color:var(--accent)}}summary{{cursor:pointer;color:var(--ink2)}}summary.h3{{font-size:15px;font-weight:650;color:var(--ink);margin:22px 0 6px}}li.more{{list-style:none;margin-left:-16px}}
nav.tabs{{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--line);margin:16px 0 8px;position:sticky;top:0;background:var(--bg);z-index:5}}
nav.tabs a{{padding:8px 12px;color:var(--ink2);text-decoration:none;border-bottom:2px solid transparent;font-weight:600}}nav.tabs a.on{{color:var(--ink);border-bottom-color:var(--accent)}}
body.js section.tab{{display:none}}body.js section.tab.on{{display:block}}section.tab>h2:first-child,section.tab>.head:first-child{{margin-top:12px}}
.warnline{{border-left:4px solid var(--warn);padding:6px 10px;background:var(--panel);margin:8px 0}}ul.notes{{max-width:1000px;color:var(--ink2)}}details.small-print{{margin-top:24px}}
.strip{{display:flex;flex-wrap:wrap;gap:2px;max-width:520px}}.strip i{{width:10px;height:10px;border-radius:2px;border:1px solid var(--line)}}.subs i{{flex:1;height:4px;border-radius:1px;outline:1px solid rgba(255,255,255,.6)}}
@media(max-width:700px){{.barcell{{width:auto;min-width:120px}}td.small,th.small{{display:none}}th{{white-space:nowrap}}}}
</style></head><body><main>
<h1>{_esc(c.name)}: detection coverage</h1>
<div class="sub">ATT&amp;CK <b>Enterprise</b> v{_esc(attack_version())} · platforms: <b>{_esc(", ".join(sorted(scope_plats)))}</b> · ICS and Mobile not assessed</div>
{"" if plat_cfg else '<p class="warnline">No PLATFORMS= in environment.env, so every ATT&amp;CK platform is assessed. Set the platforms this environment has.</p>'}
<div class="meta">Generated {today} · rules pulled {mtime(c / "rule_config.yaml")} · telemetry {mtime(inputs.current(c, "inventory"))} · rule evidence {mtime(inputs.current(c, "rule_health"))} · MITRE calculator {(_esc(calc_ver) + " run " + calc_run) if calc_ver else "not run"} · tools {_esc(tool_versions())}</div>
<nav class="tabs">{"".join(f'<a href="#{k}" data-tab="{k}">{v}</a>' for k, v in TABS)}</nav>

<section class="tab" id="tab-overview">
{headline_html}
<h2>Coverage funnel</h2><p class="why">Percentages are of the techniques in scope. Working detection is {_pct(len(an["working"]), an["telemetry"])} of what the telemetry supports today.{"" if an["variant_rate"] is None else f" {an['variant_rate'] * 100:.0f}% of the Atomic Red Team variants tested so far fired."}</p>
<div class="wrap"><table>{f'<thead><tr><th>Stage</th><th></th><th class="n">Techniques</th><th class="n">% of scope</th><th class="n">since {prev_date}</th></tr></thead>' if prev_date else ""}<tbody>{funnel_html}</tbody></table></div>
<div class="group">Techniques in scope ({len(rows)})</div><div class="tiles">
{tile(f"{n['detected_by_rules']} ({pct(n['detected_by_rules'], len(rows))})", "Detected by SIEM rules", f"{n['validated_by_rules']} validated by test", "good")}
{tile(st["limited"], "Limited", "fires, but noisy or narrow", "warn")}
{tile(st["unverified"], "Unverified", "rule deployed, no evidence yet")}
{tile(st["hand"], "Scored by hand", "no SIEM rule; not counted")}
{tile(st["buildable"], "Data, no rule", "every input of a MITRE route seen", "info")}
{tile(st["thin"], "Some data", f"{n['one_short']} of them one input short", "warn")}
{tile(f"{st['blind']} ({pct(st['blind'], len(rows))})", "No data seen", "platform in the SIEM, route inputs missing", "bad")}
{tile(st["unseen"], "Platform not seen", "no logs from the route's platform", "warn")}
{tile(st["unknown"], "Can't tell", "no MITRE route, or inputs that can't be measured")}
{tile(single, "One rule only", "detected techniques with a single rule")}</div>
<div class="group">Security products in SecOps (not in the funnel)</div><div class="tiles">
{tile(n["product_detected"] if n["product_export"] else "-", "Detected by a product", "techniques in product alerts, 30 days" if n["product_export"] else "no product_alerts export yet", "info" if n["product_detected"] else "")}
{tile(n["product_only"] if n["product_export"] else "-", "Product only", "no SIEM detection for these")}</div>
<details class="small-print"><summary>What this doesn't measure</summary><p class="why">Empty fields: a data type that arrives without the field a rule needs only shows up as a rule that never fires. Whether a rule catches a real attack: only a test proves that (Validated). Robustness for cloud and SaaS rules: MITRE scores Windows Event Log and Sysmon fields only. What security products block without alerting: the SIEM never sees it; only product alerts with an ATT&amp;CK id are counted above{"" if n["product_export"] else " (export shared/queries/product_alerts.yaral to see them)"}.</p></details>
</section>

<section class="tab" id="tab-actions">
{_actions_section(actions, _esc)}
<h2>Detectable but not detected</h2><p class="why">No rule covers these techniques, but the SIEM has the data: {len(buildable)} with every input of a MITRE route seen, then {len(short)} one input short (the missing input is named). Each group is sorted by how many ATT&amp;CK groups use the technique.{cand_note}</p>
<input class="f" placeholder="Filter…" data-t="build"><div class="scroll"><table id="build"><thead><tr><th>ID</th><th>Technique</th><th>Tactics</th><th class="n">Groups using it</th><th>Route (platform)</th><th class="n">Inputs seen</th><th>Missing</th><th class="n">Sigma candidates</th></tr></thead>
<tbody>{build_html}</tbody></table></div>
</section>

<section class="tab" id="tab-telemetry">
{_telemetry_section(plat_summary, obs, _esc, c.name)}
<div class="tiles">
{tile(f"{sum(1 for p in plat_summary if p['observed'] and p['routes'])} / {sum(1 for p in plat_summary if p['routes'])}", "Platforms seen", "with a log type in SecOps", "info")}
{tile(lt_status["unused"], "Unused log types", "mapped to ATT&CK, no rule reads them", "warn" if lt_status["unused"] else "")}
{tile(lt_status["no ATT&CK mapping"], "Unmapped log types", "event types not in the mapping table")}
{tile(len(obs.get("unplaced") or {}), "Unplaced log types", "place them with --ask", "warn" if obs.get("unplaced") else "")}</div>
<h2>Log types</h2><p class="why">What each log type is used for. Triggered: rules that fired on it in the last 90 days (rule_logtypes export). Named: rules that filter on it. Via event type: rules that filter only on an event type it sends. Unused: mapped to ATT&amp;CK, but no rule reads it. Build potential: techniques with data and no rule that it could support.</p>
<input class="f" placeholder="Filter…" data-t="lt"><div class="scroll"><table id="lt"><thead><tr><th>Log type</th><th>Status</th><th class="n">Events</th><th class="n">Rules triggered on it</th><th class="n">Rules naming it</th><th class="n">Rules via event type</th><th class="n">Build potential</th><th>ATT&amp;CK data types</th><th>Event types</th></tr></thead>
<tbody>{lt_html}</tbody></table></div>
</section>

<section class="tab" id="tab-attack">
{_matrix_section(rows, ti, scope_plats, _esc, support, product)}
<h2>Technique depth</h2><p class="why">How much of each technique the rules cover. Data paths: the ATT&amp;CK data types the technique needs here, and how many its rules read. ART: Atomic Red Team variants fired / tested, of those available. MITRE implementations and robustness come from MITRE's Detection Coverage Calculator; robustness runs from 1 (keys on values an attacker controls) to 5 (core to the technique). Depth uses ART once 3 or more variants are tested, then implementations, then data paths: deep 67%+, partial 34-66%, shallow below.{"" if rob else " <b>The calculator hasn't been run for this environment.</b>"} Working techniques: {depth_counts["deep"]} deep, {depth_counts["partial"]} partial, {depth_counts["shallow"]} shallow, {depth_counts["unknown"]} unknown.</p>
<input class="f" placeholder="Filter…" data-t="depth"><div class="scroll"><table id="depth"><thead><tr><th>ID</th><th>Technique</th><th>State</th><th class="n">Rules</th><th class="n">Data paths read</th><th>Paths not read</th><th class="n">ART fired/tested</th><th class="n">MITRE implementations</th><th class="n">Robustness</th><th>Depth</th></tr></thead>
<tbody>{"".join(depth_rows)}</tbody></table></div>
</section>

<section class="tab" id="tab-threats">
{threat_section}
</section>

<section class="tab" id="tab-rules">
<h2>Rules ({len(rules)} enabled)</h2><div class="tiles">
{tile(rs["firing"], "Firing", f"in the last {days} days", "good")}
{tile(len(noisy), "Noisy", noisy_def, "warn")}
{tile(rs["stale"], "Stale", f"last fired over {days} days ago")}
{tile(rs["never fired"], "Never fired", "rare, or broken", "warn")}
{tile(len(untagged), "Untagged", "no ATT&CK tag: invisible in coverage", "bad" if untagged else "")}
{tile(rs["not in export"] + rs["no export"], "No evidence", "missing from the rule health export")}
{tile(sum(1 for x in review if x["priority"] == "high"), "Review: high", f"{len(review)} rules flagged (rule_review.csv)", "bad" if any(x["priority"] == "high" for x in review) else "")}</div>
<h2>Rules that need tuning</h2><p class="why">Noisy ({noisy_def}), or in the top 10% by volume with no confirmed true positive. Rules that never fired are in the rule review.</p>
<div class="scroll"><table><thead><tr><th>Rule</th><th>Why</th><th class="n">Detections</th><th class="n">True pos.</th><th>Techniques</th></tr></thead><tbody>{tuning_html or '<tr><td colspan="5">None flagged.</td></tr>'}</tbody></table></div>
<h2>Most useful rules</h2><p class="why">Working rules first, then by techniques where it is the only rule (sole), confirmed true positives, data paths no other rule for the technique reads, and how many ATT&amp;CK groups use its techniques. Losing a rule near the top loses coverage.</p>
<div class="scroll"><table><thead><tr><th>Rule</th><th>State</th><th class="n">Sole</th><th class="n">True pos.</th><th class="n">Unique paths</th><th class="n">Prevalence</th><th class="n">Robustness</th><th>Techniques</th></tr></thead><tbody>{useful_html}</tbody></table></div>
{quality_section}
<h2>All rules</h2><p class="why">Enabled rules from the last pull, with their evidence. Firing = fired in the last {days} days; false positives come from case closure reasons.</p>
<input class="f" placeholder="Filter…" data-t="rules"><div class="scroll"><table id="rules"><thead><tr><th>Rule</th><th>State</th><th>Last fired</th><th class="n">Detections</th><th class="n">Not malicious</th><th>Techniques</th><th>Filters on</th><th>Triggered on</th></tr></thead>
<tbody>{rule_html}</tbody></table></div>
<h2>Hygiene</h2><ul>{"".join(hyg) or "<li>Nothing to fix.</li>"}</ul>
</section>
</main><script>
document.body.classList.add("js");
const show=k=>{{const ok=[...document.querySelectorAll("section.tab")].some(x=>x.id==="tab-"+k);if(!ok)k="overview";
document.querySelectorAll("section.tab").forEach(x=>x.classList.toggle("on",x.id==="tab-"+k));
document.querySelectorAll("nav.tabs a").forEach(a=>a.classList.toggle("on",a.dataset.tab===k))}};
addEventListener("hashchange",()=>{{show(location.hash.slice(1));scrollTo(0,0)}});show(location.hash.slice(1));
document.querySelectorAll("table").forEach(t=>{{const r=t.tBodies[0]&&t.tBodies[0].rows[0],h=t.tHead&&t.tHead.rows[0];
if(r&&h)[...r.cells].forEach((c,i)=>{{if(c.classList.contains("small")&&h.cells[i])h.cells[i].classList.add("small")}})}});
document.querySelectorAll("input.f").forEach(i=>i.addEventListener("input",()=>{{const q=i.value.toLowerCase();
document.querySelectorAll("#"+i.dataset.t+" tbody tr").forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?"":"none")}}));
document.querySelectorAll("th").forEach((th,ix)=>th.addEventListener("click",()=>{{const tb=th.closest("table").tBodies[0],c=[...th.parentNode.children].indexOf(th),
n=th.classList.contains("n"),d=th.dataset.d=th.dataset.d==="a"?"d":"a",v=t=>{{const s=t.cells[c]?.textContent.trim()||"";return n?parseFloat(s.replace(/[^0-9.-]/g,""))||0:s.toLowerCase()}};
[...tb.rows].sort((a,b)=>(v(a)>v(b)?1:v(a)<v(b)?-1:0)*(d==="a"?1:-1)).forEach(r=>tb.appendChild(r))}}));
</script></body></html>"""
    out = out_dir(c) / f"1_{c.name}_dashboard.html"
    write_text(out, page)
    print(f"{c.name}: {len(rows)} techniques in scope - detected {covered}, limited {st['limited']}, unverified "
          f"{st['unverified']}, by hand {st['hand']}, data/no rule {st['buildable']}, some data {st['thin']}, no data seen {st['blind']}, platform not seen {st['unseen']}, can't tell {st['unknown']}; "
          f"{lt_status['unused']} unused log types; {len(rules)} rules ({rs['firing']} firing)")
    print(f"open: {out}")
