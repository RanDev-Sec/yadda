"""procedures - the environment's threats as the tools and campaigns they use, from ATT&CK.

ATT&CK links each group to the software it uses (Cobalt Strike, Mimikatz ...) and each software and campaign to the
techniques it performs, with a "procedure example" sentence for each link. Detecting how a tool behaves can cover
several techniques at once. Every row is a relationship MITRE published.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from delib.cache import per_environment
from delib.attack import stix_objects

_index = None


def _clean(text: str) -> str:
    """Procedure example without citations and markdown links: '[Carbanak](https://...) checks ...' -> 'Carbanak checks ...'"""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"</?code>", "`", text)
    return re.sub(r"\s+", " ", text).strip()


def index() -> dict:
    """{'groups': {G-id: {...}}, 'software': {S-id: {...}}, 'campaigns': {C-id: {...}}} with techniques and
    procedure text per technique, from the local ATT&CK data."""
    global _index
    if _index:
        return _index
    objs = [o for o in stix_objects() if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by = {o["id"]: o for o in objs}
    ext = lambda o: next((r.get("external_id") for r in o.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), "")
    kinds = {"intrusion-set": "groups", "malware": "software", "tool": "software", "campaign": "campaigns"}
    out = {k: {} for k in set(kinds.values())}
    for o in objs:
        if o["type"] in kinds:
            out[kinds[o["type"]]][ext(o)] = {"id": ext(o), "name": o["name"], "type": o["type"],
                                             "platforms": set(o.get("x_mitre_platforms") or []),
                                             "aliases": sorted(set(o.get("aliases") or o.get("x_mitre_aliases") or [])
                                                               - {o["name"]}),
                                             "techniques": {}, "software": set(), "groups": set(), "campaigns": set()}
    key = {o["id"]: (kinds[o["type"]], ext(o)) for o in objs if o["type"] in kinds}
    for r in objs:
        if r["type"] != "relationship" or r["source_ref"] not in key:
            continue
        kind, sid = key[r["source_ref"]]
        tgt = by.get(r["target_ref"])
        if tgt is None:
            continue
        me = out[kind][sid]
        if r["relationship_type"] == "uses" and tgt["type"] == "attack-pattern":
            me["techniques"][ext(tgt)] = _clean(r.get("description", ""))
        elif r["relationship_type"] == "uses" and tgt["type"] in ("malware", "tool"):
            me["software"].add(ext(tgt))
            if kind in ("groups", "campaigns") and ext(tgt) in out["software"]:
                out["software"][ext(tgt)][kind].add(sid)
        elif r["relationship_type"] == "attributed-to" and kind == "campaigns" and tgt["type"] == "intrusion-set":
            me["groups"].add(ext(tgt))
            out["groups"][ext(tgt)]["campaigns"].add(sid)
    _index = out
    return out


HOST = {"Windows", "Linux", "macOS"}


def step_platforms(tid: str) -> set:
    """Where an intrusion step with this technique happens when nothing more is known: on hosts if the technique
    runs on hosts, else wherever ATT&CK says it runs."""
    from delib.attack import tech_index
    ps = set(tech_index()["techs"].get(tid, {}).get("platforms") or ())
    return (ps & HOST) or ps


def context_state(row: dict, platforms: set) -> str:
    """The technique's state for a tool or step running on `platforms`: 'elsewhere' when it is detected only by
    rules on other platforms."""
    from delib.facts import detected_on
    if row["state"] in ("validated", "detected") and platforms and not detected_on(row, platforms):
        return "elsewhere"
    return row["state"]


GAP_ORDER = ["elsewhere", "limited", "unverified", "hand", "buildable", "thin", "blind", "unseen", "unknown"]


def for_threats(threats: list, states: dict) -> dict:
    """The environment's threat groups as tools and campaigns.
    threats: [(label, group id, techniques)] (priorities._threat_list); states: {technique: state row}.
    -> {'software': [rows], 'campaigns': [rows], 'procedures': [rows]}. Out-of-scope techniques are left out and
    counted. A technique counts as detected for a tool only on a platform ATT&CK lists for the tool; for groups and
    campaigns, on the platform the step would happen on (step_platforms)."""
    idx = index()
    gids = {gid for _, gid, _ in threats if gid.startswith("G")}
    names = {gid: label for label, gid, _ in threats if gid}

    def ctx(item, t):
        return context_state(states[t], item["platforms"] if item["type"] in ("malware", "tool") and item["platforms"]
                             else step_platforms(t))

    def summarise(item, used_by):
        ts = [t for t in item["techniques"] if t in states]
        cs = {t: ctx(item, t) for t in ts}
        st = Counter(cs.values())
        detected = st["validated"] + st["detected"]
        gaps = sorted((t for t in ts if cs[t] not in ("validated", "detected")),
                      key=lambda t: (GAP_ORDER.index(cs[t]), t))
        return {"id": item["id"], "name": item["name"], "type": item["type"].replace("intrusion-set", "group"),
                "used_by": sorted(names.get(g, g) for g in used_by), "techniques": len(ts),
                "out_of_scope": len(item["techniques"]) - len(ts), "detected": detected,
                "states": st, "gaps": gaps, "ids": sorted(ts), "context": cs,
                "platforms": sorted(item["platforms"])}

    soft = defaultdict(set)
    for g in gids:
        for s in idx["groups"].get(g, {}).get("software", ()):
            soft[s].add(g)
    camps = {c: idx["campaigns"][c] for g in gids for c in idx["groups"].get(g, {}).get("campaigns", ())}
    software = [summarise(idx["software"][s], gs) for s, gs in soft.items() if s in idx["software"]]
    campaigns = [summarise(c, c["groups"] & gids) for c in camps.values()]
    order = lambda r: (-len(r["used_by"]), -(r["techniques"] - r["detected"]), r["name"])
    procedures = []
    for kind, items in (("software", soft), ("group", {g: {g} for g in gids})):
        for sid in items:
            item = idx["software" if kind == "software" else "groups"].get(sid)
            if not item:
                continue
            for t, text in item["techniques"].items():
                if t in states and text:
                    procedures.append({"technique": t, "state": ctx(item, t), "by": f"{item['name']} ({sid})",
                                       "kind": kind, "used_by": ", ".join(sorted(names.get(g, g) for g in items[sid])),
                                       "procedure": text})
    procedures.sort(key=lambda p: (p["state"] in ("validated", "detected"), p["technique"], p["by"]))
    return {"software": sorted(software, key=order), "campaigns": sorted(campaigns, key=order), "procedures": procedures}


def threat_names(threats: list) -> dict:
    """{name or alias: environment threat label} for matching published material (Attack Flow titles) to the
    environment's threats: the groups' names and aliases, their campaigns, and the malware they use. Tools (net, at,
    Tor ...) are left out: their names are ordinary words."""
    idx = index()
    out = {}
    for label, gid, _ in threats:
        g = idx["groups"].get(gid) or idx["campaigns"].get(gid)
        if not g:
            continue
        short = label.split(" (")[0]
        for n in [g["name"], *g["aliases"]]:
            out.setdefault(n, short)
        for cid in g.get("campaigns", ()):
            out.setdefault(idx["campaigns"][cid]["name"], short)
        for sid in g.get("software", ()):
            sw = idx["software"].get(sid)
            if sw and sw["type"] == "malware":
                for n in [sw["name"], *sw["aliases"]]:
                    if len(n) >= 4:
                        out.setdefault(n, f"{short} (via {sw['name']})")
    return out


@per_environment(key=lambda limit=10: limit)
def threat_context(c, limit: int = 10) -> dict:
    """The environment's threats beyond single techniques, from published MITRE/CTID data: software, campaigns and
    procedure examples (ATT&CK), intrusions as ordered steps (Attack Flow) and techniques they probably also use
    (TIE, inferred and not counted)."""
    from delib import flows, inference
    from delib.facts import scope_states
    from delib.priorities import _threat_list
    rows, _, _ = scope_states(c)
    states = {r["id"]: r for r in rows}
    threats = _threat_list(c)
    out = for_threats(threats, states) if threats else {"software": [], "campaigns": [], "procedures": []}
    out["flows"] = flows.for_environment(states, threat_names(threats))
    out["inferred"] = [{**r, "state": context_state(states[r["technique"]], step_platforms(r["technique"]))
                        if r["technique"] in states else "out of scope"}
                       for r in inference.for_threats(threats, limit)]
    out["threats"] = [label for label, _, _ in threats]
    return out
