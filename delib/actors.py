"""actors - ATT&CK groups by the sectors, countries and regions they target, from the MISP threat-actor galaxy
(https://github.com/MISP/misp-galaxy) and the wording of MITRE's own group descriptions."""
from __future__ import annotations


import datetime as dt

import json
import re
from delib.config import envdir, die, download, raw_url, read_env, set_env, TOOLS, write_bytes
from delib.attack import attack
from delib.facts import scope_states


# ---------------------------------------------------------------- threat actors: sector / region targeting
MISP_PATH = "clusters/{}.json"      # in misp-galaxy, at the commit pinned in tools.lock


SECTORS = {  # canonical sector -> words/phrases as they appear in ATT&CK descriptions and MISP fields
    "Government": r"government|ministr(y|ies)|public sector|administration|embass(y|ies)|diplomat\w*|state agenc\w*",
    "Defense/Military": r"defen[cs]e|military|armed forces",
    "Financial": r"financ\w*|bank\w*|insurance|cryptocurrenc\w*|payment|fintech",
    "Energy/Utilities": r"energy|oil|gas|utilit(y|ies)|electric\w*|nuclear|power grid",
    "Telecommunications": r"telecom\w*",
    "Technology/IT": r"technology|software|IT (companies|service providers|sector)|managed service providers?|MSPs?",
    "Healthcare": r"health\w*|hospital\w*|pharmaceutical\w*|medical",
    "Education/Research": r"education\w*|universit(y|ies)|academ\w*|research institut\w*|think tanks?",
    "Manufacturing": r"manufactur\w*|industrial|engineering",
    "Aerospace/Aviation": r"aerospace|aviation|airlines?|satellite",
    "Transportation/Logistics": r"transportation|logistics|shipping|maritime",
    "Media": r"media|journalist\w*|news|broadcast\w*",
    "Retail/Hospitality": r"retail|hospitality|restaurant\w*|hotels?|e-commerce|gaming|gambling",
    "Legal/Professional": r"legal|law firms?|consult\w*",
    "NGOs/Civil society": r"NGOs?|non-governmental|civil society|activist\w*|dissident\w*|human rights|political part(y|ies)",
    "Critical infrastructure": r"critical infrastructure|water|chemical|mining|construction|agricultur\w*",
}


COUNTRY_ALIASES = {  # other spellings in MISP / ATT&CK / what people type -> MISP country galaxy name
    "United States": "United States of America", "USA": "United States of America", "US": "United States of America",
    "U.S.": "United States of America", "UK": "United Kingdom", "Britain": "United Kingdom",
    "Great Britain": "United Kingdom", "England": "United Kingdom", "Czech Republic": "Czechia",
    "Russian Federation": "Russia", "The Philippines": "Philippines", "Palestine": "Palestinian Territory",
    "Gaza": "Palestinian Territory", "Lebonon": "Lebanon", "Republic of Korea": "South Korea",
    "Korea": "South Korea", "DPRK": "North Korea", "UAE": "United Arab Emirates", "Turkiye": "Turkey",
    "Türkiye": "Turkey", "Viet Nam": "Vietnam", "Cote d'Ivoire": "Ivory Coast", "Holland": "Netherlands",
    "Burma": "Myanmar", "East Timor": "Timor Leste", "Macau": "Macao"}


DESC_ALIASES = ("United States", "Czech Republic", "Russian Federation", "Great Britain", "Britain", "Palestine",
                "Viet Nam", "Burma", "Republic of Korea", "Türkiye")   # safe to search for in prose


REGION_WORDS = {"Eastern Europe": "Eastern Europe", "Western Europe": "Western Europe", "Europe": "Europe",
                "Middle East": "Western Asia", "The Middle East": "Western Asia", "Southeast Asia": "South-eastern Asia", "South Asia": "Southern Asia",
                "East Asia": "Eastern Asia", "Central Asia": "Central Asia", "Asia-Pacific": "Asia", "APAC": "Asia",
                "Asia": "Asia", "Africa": "Africa", "North America": "Northern America", "Latin America": "Latin America",
                "South America": "South America", "Oceania": "Oceania"}


CONTINENTS = {"AS": "Asia", "EU": "Europe", "AF": "Africa", "NA": "North America", "SA": "South America",
              "OC": "Oceania", "AN": "Antarctica"}


_actor_cache = None


def _misp(name: str) -> list:
    f = TOOLS / "misp" / f"{name}.json"
    if not f.exists():
        print(f"downloading MISP {name} galaxy ...", flush=True)
        download(raw_url("misp-galaxy", MISP_PATH.format(name)), f)
    return json.load(f.open(encoding="utf-8"))["values"]


def _actors() -> dict:
    """ATT&CK groups with targeting from two sources, each value tagged with where it came from:
    M = MISP threat-actor galaxy (structured fields), D = keyword found in MITRE's own group description."""
    global _actor_cache
    if _actor_cache:
        return _actor_cache
    a = attack()
    regions = {r["uuid"]: re.sub(r"^\d+ - ", "", r["value"]) for r in _misp("region")}
    countries = {}
    for x in _misp("country"):
        nm = x.get("description") or x["value"].title()
        sub = next((regions.get(rel["dest-uuid"]) for rel in x.get("related", []) if rel.get("dest-uuid") in regions), None)
        countries[nm] = {"iso": (x.get("meta") or {}).get("ISO", ""), "continent": CONTINENTS.get((x.get("meta") or {}).get("Continent", ""), ""),
                         "subregion": sub or ""}
    iso_name = {v["iso"]: k for k, v in countries.items() if v["iso"]}
    canon = lambda n: COUNTRY_ALIASES.get(n.strip(), n.strip())
    misp = {}
    for x in _misp("threat-actor"):
        for n in [x["value"], *((x.get("meta") or {}).get("synonyms") or [])]:
            misp.setdefault(n.strip().lower(), x)
    country_re = re.compile(r"\b(" + "|".join(sorted(map(re.escape, [*countries, *DESC_ALIASES]), key=len, reverse=True)) + r")\b")
    sector_res = {k: re.compile(r"\b(" + v + r")\b", re.I) for k, v in SECTORS.items()}
    region_re = re.compile(r"\b(" + "|".join(sorted(map(re.escape, REGION_WORDS), key=len, reverse=True)) + r")\b")
    # latest campaign activity per group (ATT&CK campaigns attributed to groups)
    last_seen = {}
    for r in a["by_id"].values():
        if r["type"] == "relationship" and r["relationship_type"] == "attributed-to":
            camp, grp = a["by_id"].get(r["source_ref"]), r["target_ref"]
            if camp and camp["type"] == "campaign" and camp.get("last_seen"):
                last_seen[grp] = max(last_seen.get(grp, ""), camp["last_seen"][:10])
    target_ctx = re.compile(r"target|victim|compromis|attack(s|ed)? (on|against)|against|focus(ed|es)? on|intrusions? (in|into|at)", re.I)
    motive = re.compile(r"financially[- ]motivated|financial gain|for financial|monetary gain|social media", re.I)
    out = {}
    for sid, g in a["by_id"].items():
        if g["type"] != "intrusion-set":
            continue
        gid = a["ext"](g)
        names = [g["name"], *g.get("aliases", [])]
        mx = next((misp[n.lower()] for n in names if n.lower() in misp), None)
        meta = (mx or {}).get("meta") or {}
        origin = iso_name.get(meta.get("country", ""), meta.get("country", ""))
        full = re.sub(r"\(Citation:[^)]*\)", "", g.get("description", ""))
        desc = " ".join(x for x in re.split(r"(?<=[.!?])\s+", full) if target_ctx.search(x))   # targeting sentences only
        desc = motive.sub(" ", desc)
        sectors, victims, regs = {}, {}, {}
        listed = lambda k: meta.get(k) if isinstance(meta.get(k), list) else [meta[k]] if meta.get(k) else []
        for s in listed("cfr-target-category") + listed("targeted-sector"):
            for k, rx in sector_res.items():
                if rx.search(s):
                    sectors.setdefault(k, set()).add("M")
        for k, rx in sector_res.items():
            if rx.search(desc):
                sectors.setdefault(k, set()).add("D")
        for v in listed("cfr-suspected-victims") + listed("suspected-victims"):
            if canon(v) in countries:
                victims.setdefault(canon(v), set()).add("M")
            elif v.strip() in REGION_WORDS:                 # MISP sometimes lists a region instead of a country
                regs.setdefault(REGION_WORDS[v.strip()], set()).add("M")
        for m in country_re.finditer(desc):
            nm, after, before = canon(m.group(1)), desc[m.end():m.end() + 12], desc[max(0, m.start() - 40):m.start()].lower()
            if nm == origin or re.match(r"(-based|-sponsored|-nexus|-linked|-backed|-affiliated|'s)", after) \
                    or re.search(r"(attributed to|affiliated with|on behalf of|associated with)\W*$", before):
                continue                                    # attribution, not a victim
            victims.setdefault(nm, set()).add("D")
        for v, src in victims.items():
            for r in (countries[v]["continent"], countries[v]["subregion"]):
                if r:
                    regs.setdefault(r, set()).update(src)
        for m in region_re.finditer(desc):
            regs.setdefault(REGION_WORDS[m.group(1)], set()).add("D")
        out[gid] = {"id": gid, "name": g["name"], "aliases": g.get("aliases", []), "origin": origin,
                    "sectors": sectors, "victims": victims, "regions": regs, "misp": bool(mx),
                    "techniques": sorted(a["actor_tech"].get(sid, set())), "last_seen": last_seen.get(sid, "")}
    _actor_cache = {"groups": out, "countries": countries}
    return _actor_cache


def cmd_actors(args):
    """yadda actors [--sector S] [--country C] [--region R] [--broad] [--environment X] [--set]  - ATT&CK groups by who they target"""
    opts, flags = {"--sector": [], "--country": [], "--region": [], "--environment": []}, set()
    it = iter(args)
    for x in it:
        if x in opts:
            opts[x] += [v.strip() for v in next(it, "").split(",") if v.strip()]
        elif x in ("--set", "--add", "--broad", "--list"):
            flags.add(x[2:])
        else:
            die(f"unknown option {x}. usage: yadda actors --sector Financial --country 'Germany' [--environment acme] [--set]")
    data = _actors()
    groups, countries = data["groups"], data["countries"]
    if "list" in flags:
        import textwrap
        wrap = lambda items: textwrap.fill(", ".join(items), 110, initial_indent="  ", subsequent_indent="  ")
        print("SECTORS (--sector; everyday words like finance, banking, hospital also work)")
        print(wrap(SECTORS))
        subs = sorted({v["subregion"] for v in countries.values() if v["subregion"]} - {"World"})
        print("\nREGIONS (--region; a --country also matches its region, --broad adds its continent)")
        print(wrap(subs))
        print(wrap(sorted({v["continent"] for v in countries.values() if v["continent"]} - {"Antarctica"})) + "   (continents)")
        print("\nCOUNTRIES (--country; not case sensitive)")
        print(wrap(sorted(countries)))
        print("  also accepted: " + ", ".join(COUNTRY_ALIASES))
        return
    sec_q = [s.lower() for s in opts["--sector"]]
    for q in sec_q:
        if not any(q in k.lower() or re.search(v, q, re.I) for k, v in SECTORS.items()):
            die(f"unknown sector '{q}'. Sectors: " + ", ".join(SECTORS))
    lower = {k.lower(): k for k in countries} | {k.lower(): v for k, v in COUNTRY_ALIASES.items()}
    ctry_q = []
    for q in opts["--country"]:
        if q.lower() not in lower:
            close = [k for k in countries if q.lower()[:4] in k.lower()][:5]
            die(f"unknown country '{q}'." + (f" Did you mean: {', '.join(close)}?" if close else "") + " See: yadda actors --list")
        ctry_q.append(lower[q.lower()])
    reg_q = [r.lower() for r in opts["--region"]] + [countries[q]["subregion"].lower() for q in ctry_q
                                                       if countries[q]["subregion"]]
    if "broad" in flags:
        reg_q += [countries[q]["continent"].lower() for q in ctry_q if countries[q]["continent"]]
    rows = []
    for g in groups.values():
        why = []
        if sec_q:
            hit = [s for s in g["sectors"] if any(q in s.lower() or re.search(SECTORS.get(s, "^$"), q, re.I) for q in sec_q)]
            if not hit:
                continue
            why.append("sector: " + ", ".join(f"{s} [{''.join(sorted(g['sectors'][s]))}]" for s in hit))
        if ctry_q or opts["--region"]:
            ch = [q for q in ctry_q if q in g["victims"]]
            rh = [r for r in g["regions"] if r.lower() in reg_q]
            if not ch and not rh:
                continue
            why.append(("country: " + ", ".join(f"{q} [{''.join(sorted(g['victims'][q]))}]" for q in ch)) if ch
                       else "region: " + ", ".join(f"{r} [{''.join(sorted(g['regions'][r]))}]" for r in rh))
        level = 0 if any(w.startswith("country") for w in why) else 1 if any(w.startswith("region") for w in why) else 2
        rows.append((level, g, "; ".join(why)))
    have = {r["id"]: r["state"] for r in scope_states(envdir(opts["--environment"][0]))[0]} if opts["--environment"] else None
    rows.sort(key=lambda r: (r[0], -(int(r[1]["last_seen"][:4]) if r[1]["last_seen"] else 0), -len(r[1]["techniques"])))
    with_sector = sum(1 for g in groups.values() if g["sectors"])
    with_geo = sum(1 for g in groups.values() if g["victims"] or g["regions"])
    print(f"{len(rows)} ATT&CK groups match. Targeting data exists for {with_sector}/{len(groups)} groups (sector) and "
          f"{with_geo}/{len(groups)} (country/region); groups without it can't match.")
    print("Sources: [M] MISP threat-actor galaxy, [D] wording in MITRE's group description. Origin = MISP attribution.\n")
    hdr = f"  {'ID':6} {'Group':28} {'Origin':14} {'Last campaign':13} {'Techn.':>6}"
    print(hdr + (f" {'Detected':>8} {'Data/no rule':>12}" if have is not None else "") + "  Why it matches")
    for _, g, why in rows:
        line = f"  {g['id']:6} {g['name'][:28]:28} {g['origin'][:14]:14} {g['last_seen'] or '-':13} {len(g['techniques']):>6}"
        if have is not None:
            ts = [t for t in g["techniques"] if t in have]          # on the environment's platforms
            det = sum(1 for t in ts if have[t] in ("detected", "validated"))
            buildable = sum(1 for t in ts if have[t] == "buildable")
            line += f" {(f'{100 * det / len(ts):.0f}%' if ts else '-'):>8} {buildable:>12}"
        print(line + "  " + why)
    if "set" in flags or "add" in flags:
        if not opts["--environment"]:
            die("--set / --add need --environment")
        if not (sec_q or ctry_q or opts["--region"]):
            die("--set / --add need at least one --sector, --country or --region (otherwise every group matches)")
        if not rows:
            die("no groups matched, so THREATS= was left unchanged")
        c = envdir(opts["--environment"][0])
        envf = c / "environment.env"
        write_bytes(envf.with_name(f"environment.env.{dt.datetime.now():%Y%m%d-%H%M%S}.bak"), envf.read_bytes())
        old = read_env(envf).get("THREATS", "")
        new = [g["id"] for _, g, _ in rows]
        if "add" in flags:
            new = list(dict.fromkeys([x.strip().strip("\"'") for x in old.split(",") if x.strip().strip("\"'")] + new))
        set_env(c, "THREATS", ",".join(new))
        print(f"\nTHREATS= written to {envf} ({len(new)} entries; previous file backed up next to it)"
              " - yadda dashboard shows coverage per group")
