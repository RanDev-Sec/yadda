"""routes - what telemetry is seen, per ATT&CK platform, and which MITRE detection routes it supports.

ATT&CK 18+ gives every technique one detection strategy with one analytic per platform; each analytic lists its
inputs (a data component plus MITRE's example log source, e.g. "Application Log Content" from m365:purview).
An analytic is a *route*: a way to detect the technique on that platform.

An input counts as seen only when a log type that belongs to the analytic's platform delivers that data component
(shared/log_type_platforms.csv says which platform a SecOps log type is; shared/udm_event_type_to_data_component.csv
says which data components its events carry). So Windows logons never satisfy a Microsoft 365 route.

A platform with no log types is reported as "not observed in the SIEM", not as unused.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from delib.cache import per_inventory
from delib.attack import EXTERNAL_DCS
from delib.config import SHARED, read_csv
from delib.telemetry import _mapping, _read_inventory, _row_dcs, present

NETWORK = "network"          # log types that watch traffic (firewalls, flow, proxies, DNS): network inputs, any platform
ALERTS = "alerts"            # security-product alert feeds: never telemetry, never make a platform seen
HOST = {"Windows", "Linux", "macOS"}
# UDM principal.platform values -> ATT&CK host platforms (from the host_os export; other values are ignored)
UDM_OS = {"WINDOWS": "Windows", "LINUX": "Linux", "MAC": "macOS"}
# Traffic itself is what a network sensor sees, on any platform. A host's own connection events ("Network Connection
# Creation") only count from a sensor where MITRE's analytic names one (NSM:..., flow logs) - on Windows it names Sysmon.
NETWORK_DCS = {"Network Traffic Flow", "Network Traffic Content"}
NETWORK_SOURCES = ("NSM:", "Network Traffic", "AWS:VPCFlowLogs", "PF:", "networkdevice:Firewall", "zeek:", "suricata:")

# SaaS is many unrelated products: an input naming one (saas:github) is only met by that product's logs.
# Generic names (saas:auth, saas:audit ...) are met by any SaaS log type. Product names with no row here can't be met.
SAAS_PRODUCTS = {
    "saas:github": "GITHUB.*", "saas:repoevents": "GITHUB.*", "saas:prmetadata": "GITHUB.*",
    "saas:slack": "SLACK.*", "saas:salesforce": "SALESFORCE.*", "saas:zoom": "ZOOM.*", "saas:box": "BOX.*",
    "saas:confluence": "ATLASSIAN_CONFLUENCE|CONFLUENCE.*", "saas:okta": "OKTA.*", "saas:snowflake": "SNOWFLAKE.*",
    "saas:googleworkspace": "WORKSPACE_.*|GOOGLE_WORKSPACE.*", "saas:googledrive": "WORKSPACE_.*|GOOGLE_WORKSPACE.*",
    "saas:appsscript": "WORKSPACE_.*|GOOGLE_WORKSPACE.*", "gcp:workspaceaudit": "WORKSPACE_.*|GOOGLE_WORKSPACE.*",
    "google admin audit": "WORKSPACE_.*|GOOGLE_WORKSPACE.*",
    "m365:": "OFFICE_365|AZURE_AD.*|MICROSOFT_DEFENDER_MAIL|EXCHANGE_MAIL", "azure:": "AZURE_.*",
    "aws:": "AWS_.*", "gcp:": "GCP_.*", "gcpauditlogs:": "GCP_.*",
}
SAAS_GENERIC = {"saas:auth", "saas:audit", "saas:application", "saas:access", "saas:api", "saas:collaboration",
                "saas-app:auth", "saas:integration", "saas:adminapi", "saas:finance"}


def _saas_pattern(source: str):
    """None = any SaaS log type; a regex = only that product; '' = a product we can't recognise."""
    s = source.lower()
    if s in SAAS_GENERIC:
        return None
    for key, rx in SAAS_PRODUCTS.items():
        if s == key or (key.endswith(":") and s.startswith(key)):
            return rx
    return ""


def log_type_platforms() -> list[tuple[re.Pattern, set, str]]:
    rows = read_csv(SHARED / "log_type_platforms.csv")[1]
    return [(re.compile(r["log_type"].strip(), re.I), {p.strip() for p in r["platforms"].split(";") if p.strip()},
             (r.get("product") or "").strip()) for r in rows if (r.get("log_type") or "").strip()]


def platforms_of(log_type: str, table=None, for_rules: bool = False) -> set:
    """ATT&CK platforms a log type belongs to (union of matching rows). A row marking it as an alert feed wins:
    an EDR's alert log type is not that EDR's telemetry. for_rules: the platforms a rule on it watches (an alert
    feed's vendor platforms, e.g. CS_DETECTS -> Windows, Linux, macOS)."""
    out = set()
    for rx, plats, _ in table if table is not None else log_type_platforms():
        if rx.fullmatch(log_type):
            out |= plats
    if ALERTS in out:
        return out - {ALERTS, NETWORK} if for_rules else {ALERTS}
    return out


def host_os(folder: Path | None) -> dict:
    """{log type: {Windows/Linux/macOS}} from the newest host-OS export (shared/queries/log_type_host_os.yaral) in
    the inputs folder: which operating systems a log type's events actually come from (UDM principal.platform)."""
    from delib import inputs
    if folder is None or not folder.is_dir():
        return {}
    files = sorted((p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".csv", ".tsv", ".txt")
                    and inputs.kind_of(p) == "host_os"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return {}
    from delib.telemetry import _count
    head, rows = read_csv(files[0])
    events = defaultdict(lambda: defaultdict(int))     # log type -> OS (or '' when the event carries none) -> events
    for r in rows:
        r = {k.strip().lstrip("$").lower(): (v or "").strip() for k, v in r.items() if k}
        if r.get("log_type"):
            events[r["log_type"]][UDM_OS.get(r.get("os", "").upper(), "")] += _count(r.get("event_count"))
    out = {}
    for lt, by in events.items():
        total, tagged = sum(by.values()), sum(n for o, n in by.items() if o)
        # trust the OS field only when most events carry it; an OS counts from 1% of the tagged events
        if total and tagged >= 0.8 * total:
            out[lt] = {o for o, n in by.items() if o and n >= 0.01 * tagged}
    return out


def inventory_file(c: Path) -> Path | None:
    """The telemetry inventory in use: the newest one in the environment's inputs/ folder."""
    from delib import inputs
    return inputs.current(c, "inventory")


@per_inventory
def observed(inventory: Path | None) -> dict:
    """What the SIEM shows, from a telemetry inventory export (None: nothing is known):
    {'has_inventory', 'pairs': {(platform, data component)}, 'log_types': {lt: {'events', 'platforms', 'dcs'}},
     'unplaced': {lt: events}, 'no_platform': {lt: why}}  ('*' as platform = network telemetry, counts for every
    platform). 'no_platform': log types the table knows but ATT&CK Enterprise has no platform for (a row with an empty
    platforms column); 'unplaced': log types the table doesn't know yet."""
    f = inventory
    out = {"has_inventory": bool(f), "by_pair": {}, "net": {}, "log_types": {}, "unplaced": {}, "no_platform": {},
           "alert_feeds": {}, "platforms_seen": set(), "pairs": set(), "et_platforms": defaultdict(set),
           "host_os": {}}
    if not f:
        return out
    table, mapping = log_type_platforms(), _mapping()
    oses = out["host_os"] = host_os(Path(f).parent)
    rows = present(_read_inventory(f))["rows"]
    for r in rows:
        lt = r["log_type"]
        if lt not in out["log_types"]:
            plats = platforms_of(lt, table)
            if lt in oses and plats & HOST:       # the events show which OSes it really covers
                plats = (plats - HOST) | (plats & oses[lt])
            out["log_types"][lt] = {"events": 0, "platforms": plats, "dcs": set(), "event_types": Counter()}
        info = out["log_types"][lt]
        info["events"] += r["events"]
        info["event_types"][r["event_type"]] += r["events"]
        dcs = _row_dcs(r, mapping)
        info["dcs"] |= dcs
        out["et_platforms"][r["event_type"]] |= info["platforms"] - {NETWORK, ALERTS}
        for p in info["platforms"]:
            if p == ALERTS:
                continue
            if p == NETWORK:
                for dc in dcs:
                    out["net"].setdefault(dc, set()).add(lt)
            else:
                out["platforms_seen"].add(p)
                for dc in dcs:
                    out["by_pair"].setdefault((p, dc), set()).add(lt)
    out["alert_feeds"] = {lt: i["events"] for lt, i in out["log_types"].items() if ALERTS in i["platforms"]}
    known = {lt: why for lt in out["log_types"] for rx, plats, why in table if not plats and rx.fullmatch(lt)}
    out["no_platform"] = {lt: known[lt] for lt, i in out["log_types"].items() if not i["platforms"] and lt in known}
    out["unplaced"] = {lt: i["events"] for lt, i in out["log_types"].items() if not i["platforms"] and lt not in known}
    out["pairs"] = set(out["by_pair"])                       # kept for callers that only need the pairs
    return out


def _named_product_seen(dc: str, sources: list, obs: dict) -> bool:
    """MITRE sometimes names another product's logs in a platform's analytic (Windows email collection cites
    m365:purview and azure:signinlogs). Those logs count for that input, whatever platform they're tagged with."""
    pats = [p for p in (_saas_pattern(x) for x in sources if ":" in x and not x.lower().startswith("saas:")) if p]
    return bool(pats) and any(dc in info["dcs"] and any(re.fullmatch(p, lt, re.I) for p in pats)
                              for lt, info in obs["log_types"].items())


def input_seen(platform: str, dc: str, sources: list, obs: dict) -> tuple[bool, bool]:
    """(seen, measurable-for-this-platform) for one analytic input."""
    if _named_product_seen(dc, sources, obs):
        return True, True
    lts = obs["by_pair"].get((platform, dc), set())
    if platform == "SaaS" and sources:
        pats = [_saas_pattern(x) for x in sources]
        if None not in pats:                                   # every source names a product
            known = [p for p in pats if p]
            if not known:
                return False, False                            # products we can't recognise: can't be measured
            lts = {lt for lt in lts if any(re.fullmatch(p, lt, re.I) for p in known)}
    if lts:
        return True, True
    if dc in NETWORK_DCS or any(x.startswith(NETWORK_SOURCES) for x in sources):
        if obs["net"].get(dc):
            return True, True
    return False, True


def _platform_seen(platform: str, inputs: list, obs: dict) -> bool:
    """Is this route's platform in the SIEM at all? For SaaS that means the product the route is about: Okta logs
    don't show that GitHub is (or isn't) forwarded."""
    if platform not in obs["platforms_seen"]:
        return False
    if platform != "SaaS":
        return True
    pats = {_saas_pattern(x) for i in inputs for x in i["sources"]}
    if None in pats or not any(pats):
        return True                                   # generic SaaS route: any SaaS log type is the platform
    return any(re.fullmatch(p, lt, re.I) for p in pats if p for lt in obs["log_types"])


def routes(t: dict, platforms: set, obs: dict, measurable: set) -> list[dict]:
    """One route per in-scope platform that has a MITRE analytic for the technique:
    {'platform', 'inputs': [{'dc', 'sources', 'seen', 'measurable'}], 'seen', 'needed', 'unmeasured', 'level'}
    level: 'all' = every measurable input seen; 'some'; 'none' = the platform's logs are in the SIEM but none of
    these inputs; 'unseen' = no log type of this platform is in the SIEM at all (not proof it isn't used);
    'unknown' = nothing to judge (no telemetry inventory, or no input can be measured)."""
    out = []
    for p in sorted(platforms & set(t["analytics"])):
        inputs = []
        for dc, names in sorted(t["analytics"][p].items()):
            if dc in EXTERNAL_DCS:
                continue
            sources = sorted(n for n in names if n)
            seen, meas = input_seen(p, dc, sources, obs) if dc in measurable else (False, False)
            inputs.append({"dc": dc, "sources": sources, "measurable": meas, "seen": seen})
        needed = [i for i in inputs if i["measurable"]]
        seen = [i for i in needed if i["seen"]]
        level = ("unknown" if not needed or not obs["has_inventory"] else "all" if len(seen) == len(needed)
                 else "some" if seen else "none" if _platform_seen(p, inputs, obs) else "unseen")
        out.append({"platform": p, "inputs": inputs, "seen": len(seen), "needed": len(needed),
                    "unmeasured": len(inputs) - len(needed), "level": level})
    return out


RANK = {"all": 4, "some": 3, "none": 2, "unseen": 1, "unknown": 0}


def best_route(rs: list[dict]) -> dict | None:
    """The route closest to being buildable: all inputs seen first, then the fewest inputs missing, then most seen."""
    return max(rs, key=lambda r: (RANK[r["level"]], -(r["needed"] - r["seen"]), r["seen"]), default=None)


def platform_summary(in_scope: dict, platforms: set, obs: dict, measurable: set) -> list[dict]:
    """Per in-scope platform: log types seen for it and how many of its MITRE routes are supportable, with the
    unseen inputs ranked by how many routes they would complete or advance (the onboarding to-do list)."""
    per = {p: {"platform": p, "log_types": {}, "network_log_types": {}, "routes": 0, "all": 0, "some": 0, "none": 0,
               "unseen": 0, "unknown": 0,
               "missing": defaultdict(lambda: {"techniques": set(), "completes": set(), "sources": Counter()})}
           for p in sorted(platforms)}
    for lt, info in obs["log_types"].items():
        for p in info["platforms"]:
            if p == NETWORK:              # network sensors help every platform's network inputs, but don't show
                for q in per.values():    # that the platform itself is present
                    q["network_log_types"][lt] = info["events"]
            elif p in per:
                per[p]["log_types"][lt] = info["events"]
    for tid, t in in_scope.items():
        for r in routes(t, platforms, obs, measurable):
            s = per[r["platform"]]
            s["routes"] += 1
            s[r["level"]] += 1
            unseen = [i for i in r["inputs"] if i["measurable"] and not i["seen"]]
            for i in unseen:
                # SaaS is many products: "Application Log Content" from GitHub and from Slack are separate to-dos
                product = (", ".join(sorted({x for x in i["sources"] if _saas_pattern(x) not in (None, "")})[:2])
                           if r["platform"] == "SaaS" else "")
                m = s["missing"][(i["dc"], product)]
                m["techniques"].add(tid)
                m["sources"].update(i["sources"])
                if len(unseen) == 1:
                    m["completes"].add(tid)                 # the only thing between this route and "all seen"
    for s in per.values():
        s["missing"] = sorted(({"dc": dc, "product": prod, **v,
                                "top_sources": [n for n, _ in v["sources"].most_common(3)]}
                               for (dc, prod), v in s["missing"].items()),
                              key=lambda m: (-len(m["completes"]), -len(m["techniques"]), m["dc"], m["product"]))
        s["observed"] = bool(s["log_types"])          # a log type of this platform itself is in the SIEM
        _enable_hints(s, obs.get("log_types") or {})
    return list(per.values())


# MITRE log-source names -> the SecOps log types that carry them. Most specific first: WinEventLog:Sysmon is
# WINDOWS_SYSMON, a separate log type in SecOps, not WINEVTLOG.
SOURCE_LOG_TYPES = [
    ("wineventlog:sysmon", r"WINDOWS_SYSMON|SYSMON.*", "Sysmon (WINDOWS_SYSMON)"),
    ("wineventlog", r"WINEVTLOG.*|WINDOWS_(?!SYSMON).*|POWERSHELL.*", "Windows event logs (WINEVTLOG)"),
    ("auditd", r"AUDITD.*", "auditd (AUDITD)"), ("linux", r"LINUX.*|NIX_SYSTEM|UNIX.*", "Linux syslog"),
    ("macos", r"MACOS.*", "macOS unified log"), ("networkdevice", r"CISCO_ROUTER|CISCO_IOS|CISCO_SWITCH|JUNIPER_JUNOS|ARISTA.*", "network device logs"),
    ("esxi", r"VMWARE_ESX.*|VMWARE_VSPHERE.*", "ESXi logs"), ("m365", r"OFFICE_365", "Microsoft 365 audit (OFFICE_365)"),
    ("azure", r"AZURE_AD.*|MICROSOFT_ENTRA.*|AZURE_.*", "Azure / Entra ID logs"), ("aws", r"AWS_.*", "AWS CloudTrail"),
    ("gcp", r"GCP_.*", "Google Cloud audit logs"), ("okta", r"OKTA.*", "Okta"),
    ("kubernetes", r"KUBERNETES.*|GCP_KUBERNETES.*", "Kubernetes audit"),
]


def _source_family(src: str):
    s = src.lower()
    for key, rx, label in SOURCE_LOG_TYPES:
        if s == key or s.startswith(key + ":") or (":" not in key and s.split(":")[0] == key):
            return key, rx, label
    return None


AGENTS = {"wineventlog:sysmon", "wineventlog", "auditd", "linux", "macos", "networkdevice", "esxi", "kubernetes"}


def _enable_hints(s: dict, all_log_types: dict | None = None) -> None:
    """For each missing input of a platform that is seen: is a log type that should carry it already in the SIEM?
    Then the to-do is 'enable event 4663 in WINEVTLOG' (event mapping rows tied to that log type), or 'already
    sending AUDITD; MITRE expects auditd:SYSCALL' (MITRE's log source names that log type) - not 'onboard'."""
    from delib.telemetry import _mapping
    mapping = _mapping()
    for m in s["missing"]:
        rows = [x for x in mapping if x["dc"] == m["dc"] and x["lt"]]
        carriers = sorted(lt for lt in s["log_types"] if any(x["lt"].fullmatch(lt) for x in rows))
        m["enable"] = list(dict.fromkeys(x["label"] for x in rows if any(x["lt"].fullmatch(lt) for lt in carriers)))[:5]
        fams = []                                 # MITRE's sources, most-named first, by product family
        for src in m["top_sources"]:
            f = _source_family(src)
            if f and f[0] not in [x[0] for x, _ in fams]:
                fams.append((f, src))
        if not carriers and fams and not m["product"]:
            here = lambda f: sorted(lt for lt in s["log_types"] if re.fullmatch(f[1], lt, re.I))
            (fam, src), hit = fams[0], here(fams[0][0])
            if hit:                               # it is here, but none of its mapped events give the input
                carriers = hit
                m["enable"] = [x for x in m["top_sources"] if (_source_family(x) or ("",))[0] == fam[0]][:3]
                m["by_source"] = True
            elif fam[0] in AGENTS and not any(re.fullmatch(fam[1], lt, re.I) for lt in (all_log_types or {})):
                # MITRE's main source is a host or device log that isn't in the SIEM at all: onboard it (e.g.
                # Sysmon). Vendor sources (gcp:, okta:, aws:) aren't advised: the environment may not use that vendor.
                m["onboard"] = fam[2]
                alt = next(((f, x) for f, x in fams[1:] if here(f)), None)
                if alt:                           # ... though another source MITRE names is already sent
                    m["alt"] = {"log_types": here(alt[0]), "source": alt[1]}
            else:                                 # MITRE's first source is a vendor the environment may not use: if
                alt = next(((f, x) for f, x in fams[1:] if here(f)), None)   # another source it names is sent,
                if alt:                                                       # check that one's events
                    carriers = here(alt[0])
                    m["enable"] = [x for x in m["top_sources"] if (_source_family(x) or ("",))[0] == alt[0][0]][:3]
                    m["by_source"] = True
        named = sorted({e.split()[0] for e in m["enable"]} & set(s["log_types"]))
        m["carriers"] = named or carriers         # the log types the events to enable belong to, when named


def rule_platforms(rule: dict, table=None, et_platforms: dict | None = None) -> set | None:
    """ATT&CK platforms a rule works on, from the log types it names or was seen firing on, else the product it
    names (metadata.product_name, meta data_source), else the platforms of this environment's log types that send the
    event types it filters on; None = none of these (it could run on any platform)."""
    table = table if table is not None else log_type_platforms()
    lts = set(rule.get("logtypes") or ()) | set(rule.get("observed") or ())
    if not lts:                                   # a rule naming a product instead: GITHUB -> the GITHUB log type
        lts = {re.sub(r"[^A-Z0-9]+", "_", p.upper()).strip("_") for p in rule.get("products") or ()}
    ps = set().union(*(platforms_of(lt, table, for_rules=True) for lt in lts)) if lts else set()
    if not lts and et_platforms and rule.get("eventtypes"):
        # event types only: it can fire on whatever log types send those event types for this environment
        ps = set().union(*(et_platforms.get(et, set()) for et in rule["eventtypes"]))
    ps -= {ALERTS}
    return None if not ps or NETWORK in ps else ps - {NETWORK}


SUITES = re.compile(r"OFFICE_365|WORKSPACE_.*|GOOGLE_WORKSPACE.*", re.I)   # office suites that also log some identity events


def telemetry_notes(obs: dict, platforms: list, environment: str = "<environment>") -> list[tuple[str, str]]:
    """Plain-language notes about what the SIEM shows, for the dashboard and the terminal: [(kind, text)].
    kind: 'place' (needs a person), 'alerts', 'none' (no ATT&CK platform), 'idp', 'os'."""
    out = []
    lts = obs.get("log_types") or {}
    for lt, ev in sorted((obs.get("unplaced") or {}).items(), key=lambda x: -x[1]):
        ets = ", ".join(e for e, _ in lts.get(lt, {}).get("event_types", Counter()).most_common(4))
        oses = ", ".join(sorted(obs.get("host_os", {}).get(lt, ())))
        out.append(("place", f"{lt}: {ev:,} events ({ets}{'; hosts: ' + oses if oses else ''}). Not placed on an "
                             f"ATT&CK platform, so it counts for nothing. Place it with: yadda run {environment} --ask"))
    if obs.get("alert_feeds"):
        out.append(("alerts", "not telemetry, so they don't make a platform seen: "
                    + ", ".join(f"{lt} ({ev:,})" for lt, ev in sorted(obs["alert_feeds"].items(), key=lambda x: -x[1]))))
    if obs.get("no_platform"):
        out.append(("none", "; ".join(f"{lt} ({why.split(':')[0]})"
                                                              for lt, why in sorted(obs["no_platform"].items()))))
    idp = next((p for p in platforms if p["platform"] == "Identity Provider" and p["observed"]), None)
    if idp and all(SUITES.fullmatch(lt) for lt in idp["log_types"]):
        out.append(("idp", f"Identity Provider is seen only through {', '.join(sorted(idp['log_types']))}. No sign-in "
                           "logs from the identity provider itself (Entra ID / Azure AD, Okta ...) arrive."))
    limited = {lt: sorted(o) for lt, o in (obs.get("host_os") or {}).items() if lt in lts}
    if limited:
        out.append(("os", "Host OS from the events: " + "; ".join(f"{lt} reports {', '.join(o)}" for lt, o in sorted(limited.items()))))
    return out
