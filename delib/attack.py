"""attack - indexes of the local ATT&CK Enterprise STIX bundle: technique names, revoked/deprecated IDs, what each
group, campaign and piece of software uses, and the data components each technique needs."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from delib.config import SHARED, STIX, TECH_RE, die, read_env, yaml_rt


_attack = None
_stix: dict = {}


def stix_objects() -> list:
    """The local ATT&CK Enterprise bundle's objects, read once per run (the file is large)."""
    f = STIX / "enterprise-attack" / "enterprise-attack.json"
    if not f.exists():
        die("ATT&CK data missing - run: yadda setup")
    key = (str(f), f.stat().st_mtime)
    if _stix.get("key") != key:
        _stix.clear()
        _stix.update(key=key, objects=json.load(f.open(encoding="utf-8"))["objects"])
    return _stix["objects"]


def attack() -> dict:
    """Minimal index of local ATT&CK: technique names, groups/campaigns -> techniques."""
    global _attack
    if _attack:
        return _attack
    every = stix_objects()
    ext = lambda o: next((r.get("external_id") for r in o.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), None)
    # Techniques MITRE revoked (with their replacement) or deprecated (no replacement)
    all_by_id = {o["id"]: o for o in every}
    revoked_by = {r["source_ref"]: r["target_ref"] for r in every
                  if r["type"] == "relationship" and r["relationship_type"] == "revoked-by"}
    replaced, deprecated = {}, set()
    for o in every:
        if o["type"] != "attack-pattern":
            continue
        if o.get("revoked"):
            sid, seen = o["id"], set()
            while sid in revoked_by and sid not in seen:      # follow chains of revocations
                seen.add(sid)
                sid = revoked_by[sid]
            new_obj = all_by_id.get(sid)
            if new_obj is not None and not new_obj.get("revoked"):
                replaced[ext(o)] = ext(new_obj)
        elif o.get("x_mitre_deprecated"):
            deprecated.add(ext(o))
    objs = [o for o in every if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    names, actors, actor_tech = {}, {}, defaultdict(set)
    for o in objs:
        if o["type"] == "attack-pattern":
            names[ext(o)] = o["name"]
        elif o["type"] in ("intrusion-set", "campaign"):
            for key in [ext(o), o["name"], *o.get("aliases", [])]:
                if key:
                    actors[key.lower()] = o["id"]
    for o in objs:                      # software (tools, malware) too; a group of the same name keeps the name,
        if o["type"] in ("malware", "tool"):          # the software is then reachable by its S-ID
            for key in [ext(o), o["name"], *o.get("x_mitre_aliases", [])]:
                if key and key.lower() not in actors:
                    actors[key.lower()] = o["id"]
    for r in objs:
        if r["type"] == "relationship" and r["relationship_type"] == "uses":
            tgt = by_id.get(r["target_ref"])
            if tgt and tgt["type"] == "attack-pattern" and r["source_ref"] in by_id:
                actor_tech[r["source_ref"]].add(ext(tgt))
    _attack = {"names": names, "actors": actors, "actor_tech": actor_tech, "by_id": by_id, "ext": ext,
               "replaced": replaced, "deprecated": deprecated}
    return _attack


def resolve(items: list[str]) -> tuple[list[str], list[str]]:
    """Technique IDs, ATT&CK group/campaign/software names/IDs/aliases, or threat-intel YAML files -> technique IDs."""
    a, techs, labels = attack(), [], []
    for item in items:
        path = Path(item) if Path(item).exists() else SHARED / "threat-intel" / item
        if path.suffix in (".yaml", ".yml") and path.exists():
            data = yaml_rt().load(path.open(encoding="utf-8"))
            for g in data.get("groups", []):
                techs += [str(t) for t in g.get("technique_id", [])]
                labels.append(f"{g.get('group_name')} ({path.name})")
        elif TECH_RE.fullmatch(item.upper()):
            tid = item.upper()
            new = a["replaced"].get(tid)
            techs.append(new or tid)
            labels.append(f"{tid} (replaced by {new})" if new else tid)
        elif item.lower() in a["actors"]:
            sid = a["actors"][item.lower()]
            techs += sorted(a["actor_tech"][sid])
            labels.append(f"{a['by_id'][sid]['name']} ({a['ext'](a['by_id'][sid])})")
        else:
            die(f"'{item}' is not a technique ID, an ATT&CK group/campaign/software, or a file in shared/threat-intel")
    return list(dict.fromkeys(techs)), labels


# ---------------------------------------------------------------- telemetry mapping
# Data types that describe the outside world (internet scans, registrars, malware repos), not environment telemetry.
EXTERNAL_DCS = {"Active DNS", "Passive DNS", "Domain Registration", "Certificate Registration", "Response Content",
                "Response Metadata", "Malware Content", "Malware Metadata", "Social Media"}


def _scope(c: Path) -> set:
    env = read_env(c / "environment.env") if (c / "environment.env").exists() else {}
    plats = {p.strip() for p in env.get("PLATFORMS", "").split(",") if p.strip()}
    return plats or {p for t in tech_index()["techs"].values() for p in t["platforms"]} - {"PRE"}


# ---------------------------------------------------------------- dashboard
_tech_index = None


def tech_index() -> dict:
    """Live ATT&CK techniques: name, tactics, platforms, data components needed, # groups/campaigns using it."""
    global _tech_index
    if _tech_index:
        return _tech_index
    live = [o for o in stix_objects() if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in live}
    ext = attack()["ext"]
    techs = {}
    for o in live:
        if o["type"] == "attack-pattern":
            techs[o["id"]] = {"id": ext(o), "name": o["name"], "platforms": set(o.get("x_mitre_platforms", [])),
                              "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                          if p.get("kill_chain_name") == "mitre-attack"],
                              "dcs": set(), "dcs_by_platform": defaultdict(set), "prevalence": 0,
                              "analytics": {}}      # platform -> {data component: {MITRE log source names}}
    for r in live:
        if r["type"] != "relationship":
            continue
        src, tgt = by_id.get(r["source_ref"]), r["target_ref"]
        if tgt not in techs or src is None:
            continue
        if r["relationship_type"] == "uses" and src["type"] in ("intrusion-set", "campaign"):
            techs[tgt]["prevalence"] += 1
        elif r["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
            for an_ref in src.get("x_mitre_analytic_refs", []):
                an = by_id.get(an_ref, {})
                for ls in an.get("x_mitre_log_source_references", []):
                    dc = by_id.get(ls.get("x_mitre_data_component_ref"))
                    if dc:
                        techs[tgt]["dcs"].add(dc["name"])
                        for p in an.get("x_mitre_platforms", []):
                            techs[tgt]["dcs_by_platform"][p].add(dc["name"])
                            # One analytic per platform in ATT&CK 18+: the platform's detection route and its inputs
                            techs[tgt]["analytics"].setdefault(p, {}).setdefault(dc["name"], set()).add(ls.get("name", ""))
    tactic_order = [t["x_mitre_shortname"] for m in live if m["type"] == "x-mitre-matrix"
                    for ref in m.get("tactic_refs", []) for t in [by_id.get(ref)] if t]
    # ATT&CK v18+ links techniques to data components through detection strategies -> analytics -> log sources.
    # If MITRE reshapes that again, every technique would silently become "can't tell": stop instead.
    with_dcs = sum(1 for t in techs.values() if t["dcs"])
    if techs and with_dcs < len(techs) / 2:
        die(f"only {with_dcs} of {len(techs)} ATT&CK techniques have data components in the local ATT&CK data - "
            f"MITRE may have changed how detections are modelled (version {attack_version()}). "
            "Check tools/attack-stix-data, or pin the previous version, before trusting coverage numbers.")
    _tech_index = {"techs": {t["id"]: t for t in techs.values()}, "tactic_order": tactic_order}
    return _tech_index


def _needed(t: dict, platforms: set) -> set:
    """Data components a technique needs on the environment's platforms (all platforms if none overlap)."""
    got = set().union(*(t["dcs_by_platform"].get(p, set()) for p in platforms)) if platforms else set()
    return got or set(t["dcs"])


# ---------------------------------------------------------------- threat-informed priorities
PRE_TACTICS = {"reconnaissance", "resource-development"}


def attack_version() -> str:
    return next((o.get("x_mitre_version") for o in stix_objects() if o["type"] == "x-mitre-collection"), "?")
