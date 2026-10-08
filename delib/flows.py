"""flows - published intrusions as ordered ATT&CK steps, from MITRE CTID's Attack Flow corpus.

Each flow in the corpus (https://github.com/center-for-threat-informed-defense/attack-flow, corpus/*.afb) is a
published incident (SolarWinds, Conti, NotPetya ...) drawn as a graph of ATT&CK actions joined by arrows. yadda reads it
as ordered steps and gives each step the environment's state for its technique: at which step the intrusion would
first be seen, and how many of its steps are covered. Steps without an ATT&CK id are left out.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from delib.attack import attack
from delib.config import TOOLS
from delib.procedures import context_state, step_platforms

CORPUS = TOOLS / "attack-flow" / "corpus"
DETECTED = ("validated", "detected")                           # as in the funnel
_flows = None


def _props(o: dict) -> dict:
    return {k: v for k, v in o.get("properties", []) if isinstance(k, str)}


def parse(path: Path) -> dict:
    """One .afb file -> {'name', 'description', 'actors', 'steps': [{'step', 'technique', 'name', 'description'}]}.
    Step numbers follow the arrows: an action's step is one more than the longest chain of actions leading to it;
    actions the flow draws in parallel share a step number."""
    d = json.loads(path.read_text(encoding="utf-8"))
    objs = d["objects"]
    by_inst = {o["instance"]: o for o in objs}
    owner = {}                                                  # latch -> the object it is attached to
    for o in objs:
        for anchor in (o.get("anchors") or {}).values():
            for latch in (by_inst.get(anchor) or {}).get("latches", []):
                owner[latch] = o["instance"]
    out_edges = {}
    for o in objs:
        if o["id"] == "dynamic_line" and o.get("source") in owner and o.get("target") in owner:
            out_edges.setdefault(owner[o["source"]], set()).add(owner[o["target"]])
    replaced = attack()["replaced"]
    actions = {}
    for o in objs:
        if o["id"] == "action":
            p = _props(o)
            ttp = dict(x for x in (p.get("ttp") or []) if isinstance(x, list) and len(x) == 2)
            t = (p.get("technique_id") or ttp.get("technique") or "").strip().upper()   # some flows set only ttp
            if re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                actions[o["instance"]] = {"technique": replaced.get(t, t), "name": p.get("name") or "",
                                          "description": re.sub(r"\s+", " ", p.get("description") or "").strip()}

    def next_actions(node, seen):
        """Actions reached from node, passing through non-action objects (assets, operators, malware ...)."""
        found = set()
        for n in out_edges.get(node, ()):
            if n in seen:
                continue
            seen.add(n)
            found |= {n} if n in actions else next_actions(n, seen)
        return found

    succ = {a: next_actions(a, {a}) for a in actions}
    depth = {a: 0 for a in actions}
    for _ in range(len(actions)):                               # longest path; bounded, so a drawn cycle can't hang
        changed = False
        for a, nxt in succ.items():
            for b in nxt:
                if depth[b] < depth[a] + 1 and depth[a] + 1 < len(actions):
                    depth[b], changed = depth[a] + 1, True
        if not changed:
            break
    flow = next((o for o in objs if o["id"] == "flow"), {})
    fp = _props(flow)
    actors = sorted({_props(o).get("name") or "" for o in objs if o["id"] in ("threat_actor", "campaign")} - {""})
    steps = sorted(({"step": depth[a] + 1, **v} for a, v in actions.items()),
                   key=lambda s: (s["step"], s["technique"], s["name"]))
    return {"name": fp.get("name") or path.stem, "file": path.name,
            "description": re.sub(r"\s+", " ", fp.get("description") or "").strip(), "actors": actors, "steps": steps}


def corpus() -> list[dict]:
    """Every flow in the installed corpus (yadda setup installs it); [] when it isn't installed."""
    global _flows
    if _flows is None:
        _flows = [f for f in (parse(p) for p in sorted(CORPUS.glob("*.afb"))) if f["steps"]] if CORPUS.exists() else []
    return _flows


def _words(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _matches(flow: dict, names: set) -> list:
    """Threat names (group, software or campaign names and aliases) the flow's title or actors name, as whole words."""
    hay = [_words(flow["name"])] + [_words(a) for a in flow["actors"]]
    return sorted(n for n in names if (w := _words(n)) and any(w <= h for h in hay))


def for_environment(states: dict, threat_names: dict | None = None) -> list[dict]:
    """Every flow, scored against the environment's technique states; flows naming one of its threats come first.
    states: {technique: state row}; threat_names: {name or alias: threat label}. Out-of-scope steps are kept but not
    judged; a step counts as detected only on the platform it happens on (step_platforms)."""
    threat_names = threat_names or {}
    out = []
    for f in corpus():
        steps = []
        for s in f["steps"]:
            st = states.get(s["technique"])
            steps.append({**s, "state": context_state(st, step_platforms(s["technique"])) if st else "out of scope"})
        judged = [s for s in steps if s["state"] != "out of scope"]
        covered = [s for s in judged if s["state"] in DETECTED]
        first = min((s["step"] for s in covered), default=None)
        hits = _matches(f, set(threat_names))
        out.append({"name": f["name"], "file": f["file"], "description": f["description"], "actors": f["actors"],
                    "relevant_to": sorted({threat_names[h] for h in hits}), "steps": steps,
                    "total_steps": max((s["step"] for s in steps), default=0), "actions": len(steps), "judged": len(judged),
                    "covered": len(covered), "first_seen_step": first})
    out.sort(key=lambda f: (not f["relevant_to"], -(f["covered"] / f["judged"] if f["judged"] else 0), f["name"]))
    return out
