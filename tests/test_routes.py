"""The telemetry methodology: a technique is judged by MITRE's detection routes (one analytic per platform), and
data only counts for the platform its log type belongs to. Silence is never absence."""
import pytest

from conftest import ROOT

pytestmark = pytest.mark.tools

WINDOWS = """log_type,event_type,event_count,product_event_type
WINEVTLOG,USER_LOGIN,50000,4624
WINEVTLOG,PROCESS_LAUNCH,80000,4688
WINDOWS_SYSMON,PROCESS_LAUNCH,90000,1
WINDOWS_SYSMON,NETWORK_CONNECTION,70000,3
WINDOWS_SYSMON,FILE_CREATION,40000,11
WINDOWS_SYSMON,PROCESS_OPEN,30000,10
"""
M365 = """OFFICE_365,USER_LOGIN,20000,UserLoggedIn
OFFICE_365,USER_RESOURCE_ACCESS,20000,MailItemsAccessed
OFFICE_365,EMAIL_TRANSACTION,15000,Send
"""


@pytest.fixture(scope="module")
def model():
    if not (ROOT / "tools" / "attack-stix-data").exists():
        pytest.skip("ATT&CK data not installed (yadda setup)")
    from delib import routes
    from delib.attack import tech_index
    from delib.telemetry import _dc_sources, _mapping
    return routes, tech_index()["techs"], set(_dc_sources(_mapping()))


def _obs(routes, tmp_path, text, name="inv.csv"):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return routes.observed(f)


def _route(routes, techs, measurable, obs, tid, plats):
    rs = routes.routes(techs[tid], set(plats), obs, measurable)
    return {r["platform"]: r for r in rs}


def test_windows_logons_never_stand_in_for_microsoft_365(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS)
    r = _route(routes, techs, meas, obs, "T1114.002", {"Windows", "Office Suite"})
    assert r["Office Suite"]["level"] == "unseen"            # no M365 telemetry at all: platform not seen
    assert r["Windows"]["seen"] >= 1                         # Windows route is judged on Windows data


def test_microsoft_365_logs_light_up_the_office_suite_route(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS + M365)
    r = _route(routes, techs, meas, obs, "T1114.002", {"Office Suite"})
    assert r["Office Suite"]["seen"] >= 1


def test_windows_process_events_do_not_count_for_linux(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS)
    r = _route(routes, techs, meas, obs, "T1059.004", {"Linux"})
    assert r["Linux"]["level"] == "unseen" and r["Linux"]["seen"] == 0


def test_network_telemetry_counts_for_network_inputs_on_any_platform(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nPAN_FIREWALL,NETWORK_CONNECTION,99999\n")
    r = _route(routes, techs, meas, obs, "T1046", {"Linux"})
    seen = {i["dc"] for i in r["Linux"]["inputs"] if i["seen"]}
    assert seen == {"Network Traffic Flow"}                 # network input yes, Process Creation no


def test_unplaced_log_types_count_for_nothing_and_are_listed(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nACME_HOMEGROWN,PROCESS_LAUNCH,99999\n")
    assert obs["unplaced"] == {"ACME_HOMEGROWN": 99999}
    assert not obs["pairs"]


def test_known_log_types_without_an_attack_platform_are_told_apart(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nCYBERARK,USER_LOGIN,50000\nPROOFPOINT_ON_DEMAND,EMAIL_TRANSACTION,70000\n")
    assert set(obs["no_platform"]) == {"CYBERARK", "PROOFPOINT_ON_DEMAND"} and obs["unplaced"] == {}
    assert not obs["pairs"] and "Privileged access" in obs["no_platform"]["CYBERARK"]


def test_no_inventory_means_nothing_is_known(model):
    routes, techs, meas = model
    obs = routes.observed(None)
    assert obs["has_inventory"] is False and not obs["pairs"]
    r = _route(routes, techs, meas, obs, "T1003.001", {"Windows"})
    assert r["Windows"]["level"] == "unknown"                # nothing to judge, not "missing"


def test_all_and_some_inputs_are_told_apart(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS)
    w = _route(routes, techs, meas, obs, "T1003.001", {"Windows"})["Windows"]
    assert w["level"] in ("all", "some") and 0 < w["seen"] <= w["needed"]
    assert (w["level"] == "all") == (w["seen"] == w["needed"])


def test_no_route_on_the_platforms_in_scope_is_cant_tell(model, tmp_path):
    """MITRE gives T1213.002 a Windows analytic only: an Office-Suite-only scope has no route to judge."""
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS + M365)
    assert routes.routes(techs["T1213.002"], {"Office Suite"}, obs, meas) == []
    assert routes.best_route([]) is None


def test_state_labels_never_claim_absence():
    from delib.facts import STATES
    for _, label, _, meaning in STATES:
        assert "blind" not in label.lower() and "absent" not in (label + meaning).lower()


def test_a_firewall_does_not_make_a_platform_seen(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nCISCO_ASA_FIREWALL,NETWORK_CONNECTION,99999\n")
    summary = {p["platform"]: p for p in routes.platform_summary(
        {t: techs[t] for t in ("T1114.002", "T1046")}, {"Office Suite", "Windows"}, obs, meas)}
    assert summary["Office Suite"]["observed"] is False and summary["Windows"]["observed"] is False
    assert "CISCO_ASA_FIREWALL" in summary["Windows"]["network_log_types"]


def test_saas_inputs_need_the_named_product(model, tmp_path):
    """T1213.003 Code Repositories: MITRE names saas:github - Microsoft 365 or Okta logs don't meet it."""
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS + M365 + "OKTA,USER_LOGIN,9000,\n")
    assert _route(routes, techs, meas, obs, "T1213.003", {"SaaS"})["SaaS"]["seen"] == 0
    obs = _obs(routes, tmp_path, WINDOWS + "GITHUB,USER_RESOURCE_ACCESS,9000,\nGITHUB,USER_LOGIN,9000,\n", "gh.csv")
    assert _route(routes, techs, meas, obs, "T1213.003", {"SaaS"})["SaaS"]["seen"] >= 1


def test_firewalls_do_not_stand_in_for_windows_connection_events(model, tmp_path):
    """On Windows MITRE names Sysmon for Network Connection Creation, not a network sensor."""
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nWINEVTLOG,USER_LOGIN,9999,4624\n"
                                 "CISCO_ASA_FIREWALL,NETWORK_CONNECTION,99999\n")
    w = _route(routes, techs, meas, obs, "T1046", {"Windows"})["Windows"]
    assert not any(i["seen"] for i in w["inputs"] if i["dc"] == "Network Connection Creation")


def test_platform_with_logs_but_not_these_inputs_is_none(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count,product_event_type\nWINEVTLOG,USER_LOGIN,9999,4624\n")
    assert _route(routes, techs, meas, obs, "T1003.001", {"Windows"})["Windows"]["level"] == "none"


def test_okta_logs_do_not_make_github_seen(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, WINDOWS + "OKTA,USER_LOGIN,9000,\n")
    assert _route(routes, techs, meas, obs, "T1213.003", {"SaaS"})["SaaS"]["level"] == "unseen"


def test_products_mitre_names_count_on_any_platform(model, tmp_path):
    """T1114.002's Windows analytic names m365:purview / azure:signinlogs: M365 logs count for those inputs."""
    routes, techs, meas = model
    without = _route(routes, techs, meas, _obs(routes, tmp_path, WINDOWS), "T1114.002", {"Windows"})["Windows"]["seen"]
    with_m365 = _route(routes, techs, meas, _obs(routes, tmp_path, WINDOWS + M365, "b.csv"), "T1114.002", {"Windows"})["Windows"]["seen"]
    assert with_m365 > without


def test_alert_feeds_never_make_a_platform_seen(model, tmp_path):
    routes, techs, meas = model
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nCS_ALERTS,SCAN_PROCESS,50000\n"
                                 "MICROSOFT_GRAPH_ALERT,GENERIC_EVENT,50000\nWINEVTLOG,USER_LOGIN,50000\n")
    assert set(obs["alert_feeds"]) == {"CS_ALERTS", "MICROSOFT_GRAPH_ALERT"}
    assert obs["platforms_seen"] == {"Windows"}                  # no macOS / Linux from CrowdStrike alerts
    assert routes.platforms_of("CS_EDR") == {"Windows", "Linux", "macOS"}
    assert routes.platforms_of("SENTINELONE_ALERT") == {"alerts"}  # an EDR's alert feed is not its telemetry


def test_known_log_types_from_a_live_environment_are_placed(model):
    routes, _, _ = model
    assert routes.platforms_of("VMWARE_VSPHERE") == {"ESXi"}
    assert routes.platforms_of("CISCO_SWITCH") == {"Network Devices"} == routes.platforms_of("CISCO_ACI")
    assert routes.platforms_of("DARKTRACE") == {"network"}
    for lt in ("BINDPLANE_AGENT", "UDM", "SOLARIS_SYSTEM"):
        assert routes.platforms_of(lt) == set()                  # known, no ATT&CK platform
    assert routes.platforms_of("CUSTOM_DB_AUDIT") == set()   # unknown: left for a person (yadda run --ask)


def test_host_os_export_limits_a_multi_os_edr(model, tmp_path):
    routes, techs, meas = model
    (tmp_path / "os.csv").write_text("$log_type,$os,$event_count\nCS_EDR,WINDOWS,900\nCS_EDR,,40\n", encoding="utf-8")
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nCS_EDR,PROCESS_LAUNCH,50000\n")
    assert obs["log_types"]["CS_EDR"]["platforms"] == {"Windows"} and obs["platforms_seen"] == {"Windows"}
    (tmp_path / "os.csv").unlink()
    obs = _obs(routes, tmp_path, "log_type,event_type,event_count\nCS_EDR,PROCESS_LAUNCH,50000\n")
    assert obs["platforms_seen"] == {"Windows", "Linux", "macOS"}   # no export: the table's answer


def test_sysmon_source_means_onboard_sysmon_not_check_winevtlog(model):
    routes, _, _ = model
    s = {"log_types": {"WINEVTLOG": 100}, "missing": [{"dc": "Module Load", "product": "",
                                                      "top_sources": ["WinEventLog:Sysmon"]}]}
    routes._enable_hints(s)
    m = s["missing"][0]
    assert m.get("onboard") == "Sysmon (WINDOWS_SYSMON)" and not m.get("by_source")
    assert routes._source_family("WinEventLog:Security")[0] == "wineventlog"


def test_event_type_only_rule_platform_comes_from_environment_log_types(model):
    routes, _, _ = model
    r = {"logtypes": set(), "products": set(), "eventtypes": {"PROCESS_LAUNCH"}}
    assert routes.rule_platforms(r, None, {"PROCESS_LAUNCH": {"Windows"}}) == {"Windows"}
    assert routes.rule_platforms(r) is None                      # nothing known: any platform


def test_ask_places_log_types_in_the_shared_table(model, tmp_path):
    import shutil
    from delib import placement
    routes, _, _ = model
    table = tmp_path / "t.csv"
    shutil.copy(ROOT / "shared" / "log_type_platforms.csv", table)
    answers = iter(["13", "database audit log", "", "1,12", "1,2", "test", "q"])
    n = placement.ask("acme", [("CUSTOM_DB_AUDIT", 5, ""), ("FOO", 3, ""), ("BAR.X", 2, ""), ("BAZ", 1, "")],
                      read=lambda _: next(answers), write=lambda *a: None, table=table)
    assert n == 2                                                    # FOO skipped, BAZ never reached (q)
    rows = {r[0]: r for r in (line.split(",", 2) for line in table.read_text(encoding="utf-8").splitlines())}
    assert rows["CUSTOM_DB_AUDIT"][1] == "" and rows[r"BAR\.X"][1] == "Windows;Linux"   # exact match, escaped
    tbl = [(__import__("re").compile(rx, 2), set(p.split(";")) - {""}, "") for rx, p, _ in
           (line.split(",", 2) for line in table.read_text(encoding="utf-8").splitlines()[1:])]
    assert routes.platforms_of("BAR.X", tbl) == {"Windows", "Linux"} and routes.platforms_of("BARXX", tbl) == set()
