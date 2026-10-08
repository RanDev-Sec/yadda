"""Data-loss and crash scenarios found in the October 2026 audit. Each test reproduces the reported scenario."""
import datetime as dt

import pytest

from delib import telemetry, validation
from delib.config import read_env


# ---------------------------------------------------------------- pure helpers
@pytest.mark.parametrize("raw,want", [
    ("1756629468", dt.date(2025, 8, 31)),            # epoch seconds
    ("1756629468000", dt.date(2025, 8, 31)),         # epoch milliseconds
    ("2025-08-31T08:37:00Z", dt.date(2025, 8, 31)),
    ("2025-08-31 08:37:00", dt.date(2025, 8, 31)),
    ("2025/08/31", dt.date(2025, 8, 31)),
    ("08/31/2025 08:37", dt.date(2025, 8, 31)),      # US
    ("31/08/2025", dt.date(2025, 8, 31)),            # day first (unambiguous: 31 > 12)
    ("Aug 31, 2025", dt.date(2025, 8, 31)),
    ("31 Aug 2025", dt.date(2025, 8, 31)),
    ("", None), ("0", None), ("never", None),
])
def test_when_parses_common_export_dates(raw, want):
    assert telemetry._when(raw) == want


@pytest.mark.parametrize("raw,want", [("1,234", 1234), ("1 234", 1234), ('"12"', 12), ("12.5", 12.5), ("", 0),
                                      ("N/A", 0), ("1.234.567", 1234567)])
def test_num(raw, want):
    assert telemetry._num(raw) == want


def test_inventory_skips_short_footer_and_na_rows(tmp_path, capsys):
    f = tmp_path / "inventory.csv"
    f.write_text("log_type,event_type,event_count\nWINEVTLOG,USER_LOGIN\nWINEVTLOG,PROCESS_LAUNCH,10\n"
                 "Total,,999\nOKTA,USER_LOGIN,N/A\n", encoding="utf-8")
    rows = telemetry._read_inventory(f)
    assert [(r["log_type"], r["event_type"], r["events"]) for r in rows] == [
        ("WINEVTLOG", "USER_LOGIN", 0), ("WINEVTLOG", "PROCESS_LAUNCH", 10), ("OKTA", "USER_LOGIN", 0)]
    assert "Total" not in {r["log_type"] for r in rows}


def test_inventory_semicolon_cp1252(tmp_path):
    f = tmp_path / "inventory.csv"
    f.write_bytes("log_type;event_type;event_count\nWINEVTLOG;USER_LOGIN;1.234\n".encode("cp1252"))
    assert telemetry._read_inventory(f)[0]["events"] == 1234


def test_validation_old_format_and_extra_columns(tmp_path):
    (tmp_path / "validation.csv").write_text(
        "technique,test_number,test_guid,result,analyst\nT1003.001,2a,g1,fired,bob\nT1003.001,1,g0,,\n", encoding="utf-8")
    rows = validation._load_validation(tmp_path)
    assert all("notes" in r for r in rows)
    validation._save_validation(tmp_path, rows)
    text = (tmp_path / "validation.csv").read_text(encoding="utf-8-sig")
    assert "analyst" in text and "bob" in text and "2a" in text


def test_mapping_csv_saved_by_excel_with_bom(tmp_path, monkeypatch):
    src = (telemetry.SHARED / "udm_event_type_to_data_component.csv").read_text(encoding="utf-8-sig")
    (tmp_path / "udm_event_type_to_data_component.csv").write_text("﻿" + src, encoding="utf-8")
    monkeypatch.setattr(telemetry, "SHARED", tmp_path)
    assert len(telemetry._mapping()) > 100


def test_env_quotes(tmp_path):
    (tmp_path / "e").write_text('THREATS="APT29,FIN7"\n', encoding="utf-8")
    assert read_env(tmp_path / "e")["THREATS"] == "APT29,FIN7"


# ---------------------------------------------------------------- whole commands on an isolated project folder
@pytest.mark.tools
def test_sync_after_a_manually_scored_rule_is_disabled(dehome):
    c = dehome.install()
    dehome.run("sync", "acme", check=True)
    dehome.run("score", "acme", "T1053.005", "4", "lab test passed", check=True)
    cfg = (c / "rule_config.yaml").read_text(encoding="utf-8")
    (c / "rule_config.yaml").write_text(cfg.replace("enabled: true, id: ru_acme_01", "enabled: false, id: ru_acme_01"),
                                        encoding="utf-8")
    p = dehome.run("sync", "acme")
    assert p.returncode == 0, p.out[-2000:]
    import yadda
    t = yadda.load_techniques(c)["T1053.005"]
    assert t["score"] < 1 and not t["rules"], "removed rule must not stay validated"


@pytest.mark.tools
def test_actors_set_without_matches_keeps_threats(dehome):
    c = dehome.install()
    p = dehome.run("actors", "--country", "Tuvalu", "--environment", "acme", "--set")
    assert p.returncode != 0
    assert "THREATS=APT29,FIN7" in (c / "environment.env").read_text(encoding="utf-8")


@pytest.mark.tools
def test_actors_set_keeps_a_backup(dehome):
    c = dehome.install()
    dehome.run("actors", "--sector", "finance", "--country", "Australia", "--environment", "acme", "--set", check=True)
    backups = list(c.glob("environment.env.*.bak"))
    assert backups and "THREATS=APT29,FIN7" in backups[0].read_text(encoding="utf-8")


@pytest.mark.tools
def test_review_decisions_survive_a_rule_leaving_the_list(dehome):
    c = dehome.install()
    for a in (("sync", "acme"), ("data", "acme", c / "inputs" / "inventory.csv"),
              ("evidence", "acme", c / "inputs" / "rule_health.csv", c / "inputs" / "rule_fp.csv"), ("review", "acme")):
        dehome.run(*a, check=True)
    f = c / "rule_review.csv"
    text = f.read_text(encoding="utf-8-sig")
    assert "r02_lsass_access" in text
    lines = text.splitlines()
    lines = [l.replace("r02_lsass_access,high,", "r02_lsass_access,high,", 1) for l in lines]
    import csv, io
    rows = list(csv.DictReader(io.StringIO(text)))
    for r in rows:
        if r["rule"] == "r02_lsass_access":
            r["decision"], r["notes"] = "keep", "checked with SOC lead"
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=list(rows[0]))
    w.writeheader(); w.writerows(rows)
    f.write_text(out.getvalue(), encoding="utf-8-sig")
    (c / "inputs" / "rule_fp.csv").write_text("$rule_name,$case_count,$malicious,$not_malicious\n", encoding="utf-8")
    dehome.run("evidence", "acme", c / "inputs" / "rule_health.csv", c / "inputs" / "rule_fp.csv", check=True)
    dehome.run("review", "acme", check=True)      # r02 no longer noisy -> may leave the worklist
    dehome.run("review", "acme", check=True)
    assert "checked with SOC lead" in f.read_text(encoding="utf-8-sig")


@pytest.mark.tools
def test_bad_export_does_not_replace_the_good_copy(dehome, tmp_path):
    c = dehome.install()
    good = (c / "inputs" / "inventory.csv").read_text(encoding="utf-8")
    bad = tmp_path / "bad.csv"
    bad.write_text("this,is,not\nan,inventory,export\n", encoding="utf-8")
    p = dehome.run("data", "acme", bad)
    assert p.returncode != 0
    assert (c / "inputs" / "inventory.csv").read_text(encoding="utf-8") == good
    health = (c / "inputs" / "rule_health.csv").read_text(encoding="utf-8")
    dehome.run("sync", "acme", check=True)
    p = dehome.run("evidence", "acme", bad)
    assert p.returncode != 0 and (c / "inputs" / "rule_health.csv").read_text(encoding="utf-8") == health
    assert not (c / "inputs" / "bad.csv").exists()            # a refused export is never added to inputs/


@pytest.mark.tools
def test_evidence_refuses_dates_it_cannot_read(dehome, tmp_path):
    c = dehome.install()
    dehome.run("sync", "acme", check=True)
    f = tmp_path / "health.csv"
    f.write_text("$rule_id,$display_name,$detection_time,$detection_count\n"
                 + "".join(f"ru_acme_0{i},r0{i}_x,someday {i},5\n" for i in range(1, 8)), encoding="utf-8")
    before = (c / "techniques.yaml").read_text(encoding="utf-8")
    p = dehome.run("evidence", "acme", f)
    assert p.returncode != 0 and "date" in p.out.lower()
    assert (c / "techniques.yaml").read_text(encoding="utf-8") == before


@pytest.mark.tools
def test_import_from_the_environments_own_rules_folder_is_refused(dehome):
    c = dehome.install()
    n = len(list((c / "rules").glob("*.yaral")))
    p = dehome.run("import", "acme", c / "rules")
    assert p.returncode != 0
    assert len(list((c / "rules").glob("*.yaral"))) == n


@pytest.mark.tools
def test_odd_bytes_in_a_environment_yaml_do_not_break_de(dehome):
    c = dehome.install()
    (c / "weird.yaml").write_bytes(b"a: \x81\x8d\n")
    utf16 = "a: café\n".encode("utf-16")
    (c / "ps5.yaml").write_bytes(utf16)
    p = dehome.run("help")
    assert p.returncode == 0, p.out[-1500:]
    assert (c / "ps5.yaml").read_bytes() == utf16          # UTF-16 left alone, not mangled


@pytest.mark.tools
def test_bad_days_option_is_a_message_not_a_traceback(dehome):
    dehome.install()
    dehome.run("sync", "acme", check=True)
    p = dehome.run("evidence", "acme", dehome.environments / "acme" / "inputs" / "rule_health.csv", "--days", "abc")
    assert p.returncode != 0 and "Traceback" not in p.out


def test_failed_tool_update_keeps_the_installed_copy(tmp_path, monkeypatch):
    from delib import upstream
    installed = tmp_path / "summiting-the-pyramid"
    (installed / "DCC").mkdir(parents=True)
    (installed / "DCC" / "coveragecalculator.py").write_text("# old", encoding="utf-8")
    monkeypatch.setattr(upstream, "TOOLS", tmp_path)

    def offline(args, *a, **k):
        raise SystemExit("yadda: command failed: git fetch ... (no network)")
    monkeypatch.setattr(upstream, "run", offline)
    with pytest.raises(SystemExit):
        upstream.fetch_tool("summiting-the-pyramid", "0" * 40)
    assert (installed / "DCC" / "coveragecalculator.py").read_text(encoding="utf-8") == "# old"


def test_logbook_same_day_removal_wins_and_dates_never_mix():
    from delib.facts import latest, normalise_logbooks
    import datetime as dt
    book = [{"date": dt.date(2026, 10, 1), "score": 1, "comment": "auto"},
            {"date": dt.datetime(2026, 10, 6, 10, 46), "score": 4, "comment": "manual"},
            {"date": dt.datetime(2026, 10, 6, tzinfo=dt.timezone.utc), "score": -1, "comment": "rule removed"}]
    data = {"techniques": [{"detection": [{"score_logbook": book}]}]}
    normalise_logbooks(data)
    assert len({type(e["date"]) for e in book}) == 1
    assert latest(book)[0] == -1
