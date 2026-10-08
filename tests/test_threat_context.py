"""Threat context from published MITRE / CTID data: ATT&CK software and procedures, Attack Flow, TIE."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from delib import flows, inference, procedures  # noqa: E402
from delib.attack import resolve  # noqa: E402


def _obj(kind, inst, props=None, anchors=None):
    o = {"id": kind, "instance": inst, "properties": props or []}
    if anchors is not None:
        o["anchors"] = {"0": anchors}
    return o


def _flow(tmp_path, actions, links):
    """A minimal .afb: actions [(inst, technique or None, ttp technique or None)], links [(from inst, to inst)]
    drawn the way Attack Flow Builder saves them (object -> anchor -> latch <- line -> latch <- anchor <- object)."""
    objs = [{"id": "flow", "instance": "f", "properties": [["name", "Test flow"], ["description", "x"]], "objects": []}]
    nodes = {inst for a in actions for inst in [a[0]]} | {x for link in links for x in link}
    latches = {n: [] for n in nodes}
    lines = []
    for i, (a, b) in enumerate(links):
        la, lb = f"la{i}", f"lb{i}"
        latches[a].append(la)
        latches[b].append(lb)
        objs += [{"id": "generic_latch", "instance": la}, {"id": "generic_latch", "instance": lb}]
        lines.append({"id": "dynamic_line", "instance": f"line{i}", "source": la, "target": lb, "handles": []})
    acts = {a[0]: a for a in actions}
    for n in nodes:
        if n in acts:
            _, tid, ttp = acts[n]
            props = [["name", f"step {n}"], ["technique_id", tid], ["description", "d"],
                     ["ttp", [["tactic", None], ["technique", ttp]]]]
            objs.append(_obj("action", n, props, f"anc-{n}"))
        else:
            objs.append(_obj("asset", n, [["name", n]], f"anc-{n}"))
        objs.append({"id": "vertical_anchor", "instance": f"anc-{n}", "latches": latches[n]})
    p = tmp_path / "t.afb"
    p.write_text(json.dumps({"schema": "attack_flow_v2", "objects": objs + lines}), encoding="utf-8")
    return p


def test_flow_steps_follow_arrows_through_other_objects(tmp_path):
    p = _flow(tmp_path, [("a", "T1566.001", None), ("b", None, "T1204.002"), ("c", "T1059.001", None),
                         ("d", "T1105", None)],
              [("a", "asset1"), ("asset1", "b"), ("b", "c"), ("a", "d"), ("d", "c")])
    steps = {s["technique"]: s["step"] for s in flows.parse(p)["steps"]}
    assert steps == {"T1566.001": 1, "T1204.002": 2, "T1105": 2, "T1059.001": 3}   # ttp-only id read; longest chain


def test_flow_cycle_does_not_hang(tmp_path):
    p = _flow(tmp_path, [("a", "T1566.001", None), ("b", "T1204.002", None)], [("a", "b"), ("b", "a")])
    assert len(flows.parse(p)["steps"]) == 2


def test_flow_scoring_uses_detected_definition(monkeypatch):
    monkeypatch.setattr(flows, "_flows", [{"name": "SolarWinds", "file": "s.afb", "description": "", "actors": ["APT29"],
                                          "steps": [{"step": 1, "technique": "T1", "name": "", "description": ""},
                                                    {"step": 2, "technique": "T2", "name": "", "description": ""},
                                                    {"step": 3, "technique": "T3", "name": "", "description": ""}]}])
    st = {"T1": {"state": "buildable"}, "T2": {"state": "unverified"}, "T3": {"state": "detected"}}
    f = flows.for_environment(st, {"APT29": "APT29"})[0]
    assert (f["covered"], f["judged"], f["first_seen_step"], f["relevant_to"]) == (1, 3, 3, ["APT29"])
    assert flows.for_environment(st, {"Turla": "Turla"})[0]["relevant_to"] == []


def test_tie_matches_tie_web_app():
    """Scores from TIE's own WalsRecommender.ts (run under node on the pinned model) - see the fixture's source."""
    if inference.model() is None:
        pytest.skip("TIE model not installed (yadda setup)")
    ref = json.loads((ROOT / "tests" / "fixtures" / "tie_parity_apt29.json").read_text(encoding="utf-8"))
    ours = inference.predict(set(ref["observed"]))
    assert [t for t, _ in ours[:len(ref["top"])]] == [t for t, _ in ref["top"]]
    for (t, s), (_, r) in zip(ours, ref["top"]):
        assert abs(s - r) < 1e-5, t


def test_tie_ignores_unknown_and_excludes_observed():
    if inference.model() is None:
        pytest.skip("TIE model not installed (yadda setup)")
    assert inference.predict({"T9999"}) == []
    res = inference.predict({"T1566.001", "T9999"})
    assert "T1566.001" not in {t for t, _ in res}


def test_procedure_text_cleaned():
    txt = "[Carbanak](https://attack.mitre.org/software/S0030) runs <code>whoami</code>.(Citation: Kaspersky)"
    assert procedures._clean(txt) == "Carbanak runs `whoami`."


def test_software_rows_for_fin7():
    ts, labels = resolve(["FIN7"])
    states = {t: {"state": "buildable"} for t in ts}
    states["T1059.001"] = {"state": "detected"}
    out = procedures.for_threats([(labels[0], "G0046", set(ts))], states)
    cs = next(r for r in out["software"] if r["name"] == "Cobalt Strike")
    assert cs["used_by"] == [labels[0]] and cs["techniques"] > 20
    assert all(p["procedure"] for p in out["procedures"])
    assert {p["kind"] for p in out["procedures"]} == {"software", "group"}


def test_threat_names_skip_tools():
    names = procedures.threat_names([("APT29 (G0016)", "G0016", set())])
    assert names.get("APT29") == "APT29" and "SolarWinds Compromise" in names
    assert not any(len(n) < 4 for n in names if "(via" in names[n])
    tools = {s["name"] for s in procedures.index()["software"].values() if s["type"] == "tool"}
    assert not any(n in tools for n, v in names.items() if "(via" in v)


def test_product_alerts_export(tmp_path):
    from delib import inputs
    c = tmp_path / "cust"
    (c / "inputs").mkdir(parents=True)
    f = c / "inputs" / "anything.csv"
    f.write_text("$log_type,$technique,$subtechnique,$event_count\nOKTA,T1110,T1110.003,17\nOKTA,T1110,,2\n"
                 "OFFICE_365,T1086,,1\nX,junk,,9\n", encoding="utf-8")
    assert inputs.kind_of(f) == "product_alerts"
    pa = inputs.product_alerts(c)
    assert pa["T1110.003"] == {"OKTA": 17} and pa["T1110"] == {"OKTA": 2}
    assert "T1086" not in pa and len(pa) == 3                    # revoked id mapped to its replacement


def test_balanced_actions_take_each_kind_in_turn():
    from delib.run import balanced
    acts = [{"kind": "1 telemetry", "action": f"t{i}"} for i in range(9)] + \
           [{"kind": "3 write rule", "action": f"w{i}"} for i in range(3)] + [{"kind": "4 validate", "action": "v0"}]
    top = balanced(acts, 5)
    assert [a["action"] for a in top] == ["t0", "t1", "w0", "w1", "v0"]
    assert len(balanced(acts, 50)) == len(acts)


def test_detection_counts_only_on_its_platform():
    from delib.facts import detected_on
    from delib.procedures import context_state, step_platforms
    gh = {"state": "detected", "detected_on": {"SaaS"}}
    assert detected_on(gh, {"SaaS"}) and not detected_on(gh, {"Windows"})
    assert step_platforms("T1685") <= {"Windows", "Linux", "macOS"}          # a host technique happens on hosts
    assert context_state(gh, step_platforms("T1685")) == "elsewhere"
    assert context_state({"state": "detected", "detected_on": {"*"}}, {"Windows"}) == "detected"
    assert context_state({"state": "validated", "detected_on": {"SaaS"}}, {"Windows"}) == "validated"   # a test proved it


def test_rule_platform_from_named_product():
    from delib.routes import rule_platforms
    assert rule_platforms({"logtypes": set(), "products": {"GITHUB"}}) == {"SaaS"}
    assert rule_platforms({"logtypes": {"WINEVTLOG"}, "products": {"GITHUB"}}) == {"Windows"}
    assert rule_platforms({"logtypes": set(), "products": set()}) is None


def test_partial_rerun_keeps_earlier_steps(tmp_path):
    from delib.run import _with_earlier
    first = _with_earlier(tmp_path, [("data", "ok", "32 data components"), ("review", "FAILED", "boom")])
    assert first[0] == ("data", "ok", "32 data components")
    again = _with_earlier(tmp_path, [("data", "skipped", "-data"), ("review", "skipped", "-review")])
    assert again[0][1] == "ok" and "earlier run" in again[0][2]
    assert again[1] == ("review", "skipped", "-review")                   # a failed step isn't reported as done


def test_enable_hint_names_events_of_a_log_type_already_sent():
    from delib.routes import _enable_hints
    s = {"log_types": {"WINEVTLOG": 100}, "missing": [{"dc": "File Access", "product": "", "top_sources": ["WinEventLog:Security"]}]}
    _enable_hints(s)
    m = s["missing"][0]
    assert m["carriers"] == ["WINEVTLOG"] and any("4663" in e for e in m["enable"]) and not m.get("by_source")
    s = {"log_types": {"AUDITD": 5}, "missing": [{"dc": "File Access", "product": "", "top_sources": ["auditd:SYSCALL"]}]}
    _enable_hints(s)
    assert s["missing"][0]["carriers"] == ["AUDITD"] and s["missing"][0]["by_source"]
    s = {"log_types": {}, "missing": [{"dc": "File Access", "product": "", "top_sources": ["auditd:SYSCALL"]}]}
    _enable_hints(s)
    assert s["missing"][0]["carriers"] == [] and s["missing"][0]["enable"] == []


def test_actions_that_unlock_nothing_come_last():
    from delib.run import balanced
    acts = [{"kind": "2 fix rule", "action": "untagged", "unlocks": 0}] + \
           [{"kind": "1 telemetry", "action": f"t{i}", "unlocks": 5} for i in range(3)]
    assert "untagged" not in [a["action"] for a in balanced(acts, 3)]
    assert "untagged" in [a["action"] for a in balanced(acts, 4)]


def test_rules_on_alert_feeds_watch_the_vendors_platforms():
    from delib.routes import platforms_of, rule_platforms
    assert platforms_of("GUARDDUTY") == {"alerts"}                       # never telemetry
    assert rule_platforms({"logtypes": {"GUARDDUTY"}}) == {"IaaS"}       # but a rule on it watches AWS
    assert rule_platforms({"logtypes": {"CS_DETECTS"}}) == {"Windows", "Linux", "macOS"}


def test_sync_folds_into_todays_last_entry_and_drops_template_location():
    import datetime as dt
    from delib.facts import _day, latest, sync_detections
    today = _day(dt.datetime.now(dt.timezone.utc))
    data = {"techniques": [{"technique_id": "T1685", "technique_name": "x", "detection": [{
        "applicable_to": ["all"], "location": ["", "SecOps: old"], "comment": "",
        "score_logbook": [{"date": today, "score": 3, "comment": "a"}, {"date": today, "score": 2, "comment": "b"}]}]}]}
    sync_detections(data, {})                                            # the only rule is gone
    det = data["techniques"][0]["detection"][0]
    assert latest(det["score_logbook"])[0] == -1 and det["score_logbook"][0]["score"] == 3
    sync_detections(data, {"new_rule": ["T1685"]})                       # a rule covers it again
    assert latest(det["score_logbook"])[0] == 1 and det["location"] == ["SecOps: new_rule"]


def test_host_os_needs_most_events_tagged(tmp_path):
    from delib.routes import host_os
    (tmp_path / "os.csv").write_text("$log_type,$os,$event_count\nCS_EDR,WINDOWS,10\nCS_EDR,,990\n"
                                     "S1,LINUX,500\nS1,WINDOWS,480\nS1,MAC,2\n", encoding="utf-8")
    got = host_os(tmp_path)
    assert "CS_EDR" not in got                                            # 1% tagged: the field isn't trustworthy
    assert got["S1"] == {"Linux", "Windows"}                              # 2 of 982 Mac events: noise
