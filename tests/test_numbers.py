"""Environment-facing numbers: each test pins a definition the tool states (help, dashboard text, README)."""
import json

import pytest

from conftest import in_home

pytestmark = pytest.mark.tools


def analysis(h):
    return json.loads(in_home(h, """
import json, yadda
c = yadda.envdir('acme'); a = yadda._analysis(c)
f = {lab: (n, hi) for lab, n, why, hi in a['funnel']}
depth = {t: yadda._tech_depth(t, a['depth'], a['art'], a['rob']) for t in a['working']}
rules = {r['name']: {'state': r['state'], 'tune': r['tune'], 'broken': r['broken'], 'noisy': r['noisy']} for r in a['ranked']}
print(json.dumps({'funnel': f, 'working': sorted(a['working']), 'depth': depth, 'rules': rules,
                  'ruled': sorted(a.get('ruled', []))}, default=str))
"""))


def test_cloud_techniques_are_not_zero_depth_because_mitre_cannot_score_them(acme):
    h, c = acme
    d = analysis(h)["depth"]
    for t in ("T1621", "T1530"):                      # Okta / Office 365 rules
        if t in d:
            ratio, src = d[t]
            assert src != "MITRE implementations" or ratio > 0, f"{t}: {d[t]}"


def test_funnel_stages_nest_and_count_only_enabled_rules(acme):
    h, c = acme
    h.run("score", "acme", "T1110.003", "4", "EDR detection, no SIEM rule", check=True)   # disabled rule's technique
    a = analysis(h)
    f = {k: v[0] for k, v in a["funnel"].items()}
    ruled = f["With an enabled rule"]
    assert f["Telemetry ceiling"] >= ruled >= f["Working detection"] >= f["Validated"]
    assert "T1110.003" not in a["working"]
    # enabled tagged rules in scope: r01 r02 r03 r04 r05 r06 r07 r09 r10 r12 r13 -> 11 techniques (r11 disabled)
    assert ruled == 11


def test_rule_with_detections_but_no_time_is_not_never_fired(acme):
    h, c = acme
    r = analysis(h)["rules"]["r05_okta_push_spam"]
    assert r["state"] != "never fired" and not r["broken"]
    review = (c / "rule_review.csv").read_text(encoding="utf-8-sig")
    line = next((l for l in review.splitlines() if l.startswith("r05_okta_push_spam,")), "")
    assert "never fired" not in line


def test_one_definition_of_data_no_rule_everywhere(acme):
    h, c = acme
    status = h.run("status", check=True).out
    dash = h.run("dashboard", "acme", check=True).out
    import re
    tile = int(re.search(r"data/no rule (\d+)", dash).group(1))
    row = next(l for l in status.splitlines() if l.split() and l.split()[0] == "acme").split()
    head = next(l for l in status.splitlines() if "data_no_rule" in l).split()
    assert int(row[head.index("data_no_rule")]) == tile


def test_check_uses_the_dashboard_states(acme):
    h, c = acme
    out = h.run("check", "acme", "T1053.005", "T1086", check=True).out
    assert "T1086" not in out or "T1059.001" in out              # revoked ID translated
    states = json.loads(in_home(h, """
import json, yadda
c = yadda.envdir('acme'); sp = yadda._scope(c)
ins = {t: x for t, x in yadda.tech_index()['techs'].items() if x['platforms'] & sp}
print(json.dumps({r['id']: r['state'] for r in yadda._states(c, ins, sp)[0] if r['id'] in ('T1053.005', 'T1059.001')}))"""))
    label = {"validated": "VALIDATED", "detected": "DETECTED", "limited": "LIMITED", "unverified": "UNVERIFIED",
             "buildable": "DATA, NO RULE", "thin": "THIN DATA", "blind": "NO DATA", "unknown": "CAN'T TELL"}
    for t, s in states.items():
        assert any(l.strip().startswith(label[s]) and t in l for l in out.splitlines()), (t, s, out)


def test_resolve_translates_revoked_ids():
    import yadda
    techs, labels = yadda.resolve(["T1086"])
    assert techs == ["T1059.001"]


def test_noise_threshold_options_reach_every_view(acme):
    h, c = acme
    h.run("evidence", "acme", c / "inputs" / "rule_health.csv", c / "inputs" / "rule_fp.csv", "--fp-max", "90", check=True)
    rules = analysis(h)["rules"]
    assert rules["r02_lsass_access"]["noisy"]                 # 95% not malicious
    assert not rules["r13_o365_download"]["noisy"]            # 83% not malicious: under 90
    h.run("evidence", "acme", c / "inputs" / "rule_health.csv", c / "inputs" / "rule_fp.csv", "--fp-max", "50", check=True)


def test_review_reads_scope_from_live_rule_logic_only(acme):
    h, c = acme
    review = (c / "rule_review.csv").read_text(encoding="utf-8-sig")
    line = next((l for l in review.splitlines() if l.startswith("r07_comment_and_negation,")), "")
    assert "FILE_CREATION" not in line and "USER_LOGIN" not in line


def test_volume_flag_needs_case_outcomes(acme):
    h, c = acme
    for name, r in analysis(h)["rules"].items():
        for t in r["tune"]:
            if "top-10% volume" in t:
                assert "no confirmed true positives" not in t or "case" in t
