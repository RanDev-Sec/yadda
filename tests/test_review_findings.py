"""Problems found by the independent review after the audit fixes. Each test reproduces one report."""
import csv
import datetime as dt
import io

import pytest

from delib import facts, telemetry, yaral
from delib.config import read_csv, read_env


# ---------------------------------------------------------------- dates and numbers
@pytest.mark.parametrize("raw,want", [
    ("1756598400000000", dt.date(2025, 8, 31)),          # epoch microseconds: used to crash read_health
    ("99999999999999999999999", None),                  # absurd number: None, not a crash
    ("Aug 31, 2025, 10:00:00 AM", dt.date(2025, 8, 31)),
    ("Sept 1, 2025", dt.date(2025, 9, 1)),
    ("2025-8-31", dt.date(2025, 8, 31)),
    ("2025-08-31T10:00:00Z", dt.date(2025, 8, 31)),
])
def test_more_export_dates(raw, want):
    assert telemetry._when(raw) == want


def test_day_first_is_decided_for_the_whole_column():
    col = ["31/05/2025", "05/06/2025"]
    assert telemetry.day_first(col) is True
    assert telemetry._when("05/06/2025", telemetry.day_first(col)) == dt.date(2025, 6, 5)
    assert telemetry.day_first(["05/31/2025", "05/06/2025"]) is False


def test_counts_with_thousands_dots_in_exports(tmp_path):
    f = tmp_path / "fp.csv"
    f.write_text("rule_name,case_count,malicious,not_malicious\nr1,1.234,1.000,234\n", encoding="utf-8")
    assert facts.read_fp(f)["r1"] == (1234, 1000, 234)


# ---------------------------------------------------------------- CSV
def test_csv_leading_blank_lines_and_excel_sep_hint(tmp_path):
    f = tmp_path / "x.csv"
    f.write_text("\n\nsep=;\na;b\n1;2\n", encoding="utf-8")
    head, rows = read_csv(f)
    assert head == ["a", "b"] and rows == [{"a": "1", "b": "2"}]


# ---------------------------------------------------------------- YARA-L scope
def _rule(events):
    return "rule x {\n  events:\n" + events + "\n  condition:\n    $e\n}\n"


def test_double_slash_inside_a_string_is_not_a_comment():
    s = yaral.scope(_rule('    ($e.target.url = "http://x" or $e.metadata.log_type = "P")\n'
                          '    $e.metadata.event_type = "NETWORK_HTTP"  // real comment'))
    assert s["event_types"] == {"NETWORK_HTTP"} and "P" in s["log_types"]


def test_reference_list_is_not_a_log_type():
    s = yaral.scope(_rule('    $e.metadata.log_type in %win_sources\n    $e.metadata.event_type = "PROCESS_LAUNCH"'))
    assert s["log_types"] == set()


def test_not_not_equal_counts_as_equal():
    s = yaral.scope(_rule('    not $e.metadata.event_type != "PROCESS_LAUNCH"'))
    assert s["event_types"] == {"PROCESS_LAUNCH"}


# ---------------------------------------------------------------- score logbook
def test_score_replaces_every_entry_of_today():
    today = dt.datetime.now(dt.timezone.utc)
    book = [{"date": today.replace(hour=9, minute=15), "score": 1, "comment": "older yadda"},
            {"date": facts._day(today), "score": 1, "comment": "auto"}]
    data = {"techniques": [{"technique_id": "T1003.001", "technique_name": "LSASS Memory",
                            "detection": [{"applicable_to": ["all"], "location": [""], "comment": "",
                                           "score_logbook": book}]}]}
    facts._set_score(data, "T1003.001", 4, "manual")
    log = data["techniques"][0]["detection"][0]["score_logbook"]
    assert facts.latest(log)[0] == 4 and len(log) == 1


# ---------------------------------------------------------------- commands (subprocess against a throwaway home)
@pytest.mark.tools
def test_evidence_refuses_a_header_only_or_foreign_export(dehome, tmp_path):
    c = dehome.install()
    dehome.run("sync", "acme", check=True)
    good = (c / "inputs" / "rule_health.csv").read_bytes()
    for body in ("rule_id,display_name,detection_time,detection_count\n",
                 "rule_id,display_name,detection_time,detection_count\nru_zzz,other_environment_rule,1756629468,5\n"):
        bad = tmp_path / "h.csv"
        bad.write_text(body, encoding="utf-8")
        p = dehome.run("evidence", "acme", bad)
        assert p.returncode != 0 and "Nothing was changed" in p.out
        assert (c / "inputs" / "rule_health.csv").read_bytes() == good


def test_import_of_a_folder_without_rules_changes_nothing(dehome, tmp_path):
    c = dehome.install()
    before = sorted(p.name for p in (c / "rules").iterdir())
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("no rules here", encoding="utf-8")
    p = dehome.run("import", "acme", empty)
    assert p.returncode != 0 and "nothing was changed" in p.out
    assert sorted(p.name for p in (c / "rules").iterdir()) == before


@pytest.mark.tools
def test_actors_add_with_a_quoted_threats_value(dehome):
    c = dehome.install()
    env = c / "environment.env"
    env.write_text(env.read_text(encoding="utf-8").replace("THREATS=APT29,FIN7", 'THREATS="APT29,FIN7"'),
                   encoding="utf-8")
    dehome.run("actors", "--sector", "finance", "--country", "Australia", "--environment", "acme", "--add", check=True)
    threats = read_env(env)["THREATS"].split(",")
    assert threats[:2] == ["APT29", "FIN7"] and not any('"' in t for t in threats)


def test_actors_set_without_any_filter_is_refused(dehome):
    c = dehome.install()
    p = dehome.run("actors", "--environment", "acme", "--set")
    assert p.returncode != 0
    assert "THREATS=APT29,FIN7" in (c / "environment.env").read_text(encoding="utf-8")


@pytest.mark.tools
def test_review_keeps_columns_you_added_on_flagged_rules(acme):
    h, c = acme
    f = c / "rule_review.csv"
    rows = list(csv.DictReader(io.StringIO(f.read_text(encoding="utf-8-sig"))))
    for r in rows:
        r["owner"] = "alice"
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=list(rows[0]))
    w.writeheader(); w.writerows(rows)
    f.write_text(out.getvalue(), encoding="utf-8-sig")
    h.run("review", "acme", check=True)
    again = [r for r in csv.DictReader(io.StringIO(f.read_text(encoding="utf-8-sig")))
             if r["rule"] in {x["rule"] for x in rows}]               # newly flagged rules have no owner yet
    assert again and all(r.get("owner") == "alice" for r in again)


def test_validation_results_typed_in_another_case_count(tmp_path):
    from delib import validation
    (tmp_path / "validation.csv").write_text(
        "technique,test_number,test_guid,test_name,art_platform,executor,result\n"
        "T1059.001,1,abc,x,windows,powershell,Fired\n", encoding="utf-8")
    assert validation._load_validation(tmp_path)[0]["result"] == "fired"



# ---------------------------------------------------------------- false-positive rate is a share of cases
@pytest.mark.parametrize("mal,notmal", [(0, 0), (0, 5), (3, 0), (1, 1000), (1000, 1)])
def test_fp_pct_is_never_over_100(mal, notmal):
    pct = facts.fp_pct(mal, notmal)
    assert pct is None or 0 <= pct <= 100


def test_fp_export_counts_cases_per_reason(tmp_path):
    """One case grouping many alerts from the same rule counts once (the query counts distinct cases)."""
    f = tmp_path / "fp.csv"
    f.write_text("rule_name,reason,case_count\nr1,NOT_MALICIOUS,3\nr1,MALICIOUS,1\nr1,MAINTENANCE,2\n", encoding="utf-8")
    cases, mal, notmal = facts.read_fp(f)["r1"]
    assert (cases, mal, notmal) == (6, 1, 3) and facts.fp_pct(mal, notmal) == 75
