"""layers - ATT&CK Navigator layers (https://mitre-attack.github.io/attack-navigator/).

Three layers, coloured by technique state as on the dashboard:
  <c>_detection_state.json   every in-scope technique
  <c>_threats.json           the techniques the environment's threat groups use (score = how many groups)
  <c>_check.json             what `yadda check ... --layer` asked about
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from delib.attack import attack_version
from delib.config import out_dir, write_text
from delib.facts import CONTEXT_STATES

COLOUR = {k: col for k, _, col, _ in CONTEXT_STATES}
LABEL = {k: lbl for k, lbl, _, _ in CONTEXT_STATES}


def write(c: Path, suffix: str, name: str, description: str, techniques: list[dict], platforms, used: set) -> Path:
    """techniques: [{'id', 'state', 'comment'?, 'score'?}]. The legend lists only the states used."""
    ver = attack_version()
    layer = {
        "name": name, "versions": {"attack": ver.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "description": f"{description} - {dt.date.today()}, ATT&CK Enterprise v{ver}",
        "filters": {"platforms": sorted(platforms)},
        "techniques": [{"techniqueID": t["id"], "color": COLOUR.get(t["state"], "#ffffff"),
                        "comment": t.get("comment") or LABEL.get(t["state"], t["state"]),
                        **({"score": t["score"]} if "score" in t else {}), "showSubtechniques": False}
                       for t in techniques],
        "legendItems": [{"label": lbl, "color": col} for k, lbl, col, _ in CONTEXT_STATES if k in used],
        "hideDisabled": False,
    }
    f = out_dir(c, "3_navigator_layers") / f"{c.name}_{suffix}.json"
    write_text(f, json.dumps(layer, indent=1))
    return f


def detection_state(c: Path, rows: list, platforms) -> Path:
    return write(c, "detection_state", f"{c.name} - detection state", f"yadda technique states for {c.name}",
                 [{"id": r["id"], "state": r["state"]} for r in rows], platforms, {r["state"] for r in rows})


def threats(c: Path, tp: dict, platforms) -> Path | None:
    """The threat groups' techniques, coloured by state (judged where the groups act), score = groups using it."""
    if not tp.get("n"):
        return None
    rows = tp["rows"]
    return write(c, "threats", f"{c.name} - threat groups", f"techniques of {tp['n']} threat groups (score = groups using it)",
                 [{"id": r["id"], "state": r["state"] if tp.get("assessed") else "unknown", "score": len(r["users"]),
                   "comment": f"{LABEL.get(r['state'], r['state'])}; used by {', '.join(r['users'])}"} for r in rows],
                 platforms, {r["state"] for r in rows})


def check(c: Path, label: str, techs: list, states: dict, platforms) -> Path:
    items = [{"id": t, "state": states[t]["state"] if t in states else "unknown",
              "comment": LABEL.get(states[t]["state"]) if t in states else "not on the environment's platforms"} for t in techs]
    return write(c, "check", f"{c.name} - {label}"[:80], f"yadda check {label}", items, platforms, {i["state"] for i in items})
