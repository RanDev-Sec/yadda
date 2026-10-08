"""October 2026 additions: yadda sigma candidates, rule_logtypes via yadda evidence, git import, environment names."""
import subprocess

import pytest

from delib import sigma
from delib.commands import _export_kind, _split_rules


# ---------------------------------------------------------------- Sigma -> YARA-L
RULE = """title: Test "quoted" title - with hyphen
id: 11111111-1111-1111-1111-111111111111
status: test
description: |
  Line one with "quotes"
  and a second line \\ backslash
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  filter_a:
    ParentImage|endswith: '\\\\explorer.exe'
    CommandLine|contains: 'foo'
  condition: selection and not filter_a
tags: [attack.execution, attack.t1059.003]
level: high
"""


@pytest.fixture(scope="module")
def converted():
    pytest.importorskip("sigma.backends.secops")
    r, why = sigma.convert(RULE)
    assert r, why
    return r


def test_negated_group_keeps_its_negation(converted):
    body = converted["yaral"].split("events:")[1].split("condition:")[0]
    assert body.count("!=") == 2 and " or " in body           # not (A and B) == A' or B'


def test_wrapper_is_valid_yaral(converted):
    y = converted["yaral"]
    assert y.startswith("rule sigma_test_quoted_title_with_hyphen {")
    assert "\n  condition:\n    $event1\n}" in y and "conditions:" not in y
    meta = y.split("events:")[0]
    assert all(line.count('"') % 2 == 0 or '\\"' in line for line in meta.splitlines())
    assert 'mitre_attack_technique = "T1059.003"' in y and '\\"quotes\\"' in y


def test_scope_is_read_from_the_candidate(converted):
    assert converted["scope"]["event_types"] == {"PROCESS_LAUNCH"} and converted["techniques"] == ["T1059.003"]


def test_unquoted_values_are_rejected():
    assert sigma._unquoted_value('$e.x = +R +H nocase')
    assert not sigma._unquoted_value('$e.x = "a=b" and $e.y != /c=d/ nocase and $e.z = 4')


@pytest.mark.tools
def test_de_sigma_writes_candidates_that_do_not_count(acme):
    h, c = acme
    before = h.run("status", check=True).out
    p = h.run("sigma", "acme", "--threats", check=True)
    assert "candidate rules" in p.out
    import datetime as dt
    out = h.path / "output" / "acme" / str(dt.date.today()) / "4_sigma_candidates"
    files = list(out.glob("*.yaral"))
    assert files and (out / "candidates.csv").exists()
    assert h.run("status", check=True).out == before            # candidates are not coverage


# ---------------------------------------------------------------- evidence: any order, rule_logtypes accepted
@pytest.mark.parametrize("header,kind", [
    ("$rule_id,$display_name,$detection_time,$detection_count", "rule_health"),
    ("rule_name,reason,case_count", "rule_fp"),
    ("$rule_name,$case_count,$malicious,$not_malicious", "rule_fp"),
    ("rule_name,log_type,detection_count", "rule_logtypes"),
])
def test_export_kind(tmp_path, header, kind):
    f = tmp_path / "x.csv"
    f.write_text(header + "\n", encoding="utf-8")
    assert _export_kind(f) == kind


@pytest.mark.tools
def test_evidence_takes_rule_logtypes_in_any_order(dehome, tmp_path):
    c = dehome.install()
    dehome.run("sync", "acme", check=True)
    lt = tmp_path / "lt.csv"
    lt.write_bytes((c / "inputs" / "rule_logtypes.csv").read_bytes())
    (c / "inputs" / "rule_logtypes.csv").unlink()
    dehome.run("evidence", "acme", lt, c / "inputs" / "rule_fp.csv", c / "inputs" / "rule_health.csv", check=True)
    assert (c / "inputs" / "lt.csv").read_bytes() == lt.read_bytes()        # added to inputs/ under its own name


# ---------------------------------------------------------------- import
def test_one_file_with_several_rules():
    text = "rule a {\n events:\n  $e.x = 1\n condition:\n  $e\n}\n\nrule b {\n events:\n  $e.y = 2\n condition:\n  $e\n}\n"
    assert [n for n, _ in _split_rules(text)] == ["a", "b"]


def test_import_from_git_and_case_insensitive_duplicates(dehome, tmp_path):
    repo = tmp_path / "repo"
    (repo / "secops").mkdir(parents=True)
    (repo / "secops" / "one.yaral").write_text("rule Rule_A {\n events:\n  $e.x = 1\n condition:\n  $e\n}\n", encoding="utf-8")
    (repo / "secops" / "two.yaral").write_text("rule rule_a {\n events:\n  $e.y = 2\n condition:\n  $e\n}\n", encoding="utf-8")
    (repo / "README.md").write_text("not a rule", encoding="utf-8")
    g = ["git", "-C", str(repo)]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(g + ["add", "."], check=True)
    subprocess.run(g + ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], check=True)
    dehome.run("import", "gitco", f"file://{repo}", check=True)
    names = sorted(p.name for p in (dehome.environments / "gitco" / "rules").iterdir())
    assert names == ["Rule_A.yaral", "rule_a__dup2.yaral"]


@pytest.mark.parametrize("bad", ["../evil", "a/b", "a\\b", "CON", "nul.txt", "_template", ".hidden", "x..y", ""])
def test_environment_names_stay_inside_environments(dehome, bad):
    p = dehome.run("new", bad)
    assert p.returncode != 0
    assert not (dehome.path / "evil").exists()


# ---------------------------------------------------------------- converter corrections (each found by hand review)
BASE = """title: T
id: 11111111-1111-1111-1111-111111111111
status: test
logsource: {category: CAT, product: windows}
detection:
DET
tags: [attack.t1059.003]
level: low
"""


def _events(cat, det):
    pytest.importorskip("sigma.backends.secops")
    r, why = sigma.convert(BASE.replace("CAT", cat).replace("DET\n", det + "\n"))
    assert r, why
    return r["yaral"].split("events:")[1].split("condition:")[0].strip().split("\n", 1)[1]


@pytest.mark.parametrize("cat,det,want,never", [
    ("network_connection", "  sel:\n    Image|endswith: '\\\\w.exe'\n  f:\n    DestinationPort: [80, 443]\n  condition: sel and not f",
     ["target.port != 80 and $event1.target.port != 443"], ["port = 80"]),
    ("network_connection", "  sel:\n    Image|endswith: '\\\\d.exe'\n  f:\n    DestinationIp|cidr: ['10.0.0.0/8', '192.168.0.0/16']\n  condition: sel and not f",
     ['not net.ip_in_range_cidr($event1.target.ip, "10.0.0.0/8") and not net.ip_in_range_cidr'], []),
    ("process_creation", "  sel:\n    Image|endswith: '\\\\r.exe'\n  f:\n    CommandLine: null\n  condition: sel and not f",
     ['command_line != ""'], ['command_line = ""']),
    ("process_creation", "  sel:\n    Image|endswith: '\\\\a.exe'\n  f:\n    ProcessId|gt: 100\n  condition: sel and not f",
     ["pid <= 100"], []),
    ("process_creation", "  sel:\n    CommandLine|windash|contains: ' -c '\n    Image|endswith: '\\\\cmd.exe'\n  condition: sel",
     ["($event1.target.process.command_line = / -c / nocase or"], []),
    ("process_creation", "  sel:\n    CommandLine|re: '\\s-[FTd]\\s'\n  condition: sel",
     ["/\\s-[FTd]\\s/"], ["nocase", "\\\\s"]),
    ("process_creation", "  sel:\n    Image|endswith: ['\\\\a.exe', '\\\\b.exe']\n  condition: sel",
     ["/\\\\a\\.exe$/ nocase or", "/\\\\b\\.exe$/ nocase"], []),
    ("file_event", "  sel:\n    Image|endswith: '\\\\a.exe'\n    TargetFilename|endswith: '.lnk'\n  condition: sel",
     ["principal.process.file.full_path", "target.file.full_path"], ["target.process", "file.names"]),
    ("process_creation", "  sel:\n    Image|endswith: '\\\\a.exe'\n    IntegrityLevel: High\n  condition: sel",
     ["integrity_level_rid = 12288"], ['"High"']),
])
def test_converter_corrections(cat, det, want, never):
    body = _events(cat, det)
    for w in want:
        assert w in body, body
    for n in never:
        assert n not in body, body


def test_file_event_is_a_creation():
    pytest.importorskip("sigma.backends.secops")
    r, _ = sigma.convert(BASE.replace("CAT", "file_event").replace(
        "DET\n", "  sel:\n    TargetFilename|endswith: '.lnk'\n  condition: sel\n"))
    assert '"FILE_CREATION"' in r["yaral"]


def test_udm_search_aliases_are_rejected():
    pytest.importorskip("sigma.backends.secops")
    r, why = sigma.convert(BASE.replace("CAT", "process_creation").replace(
        "DET\n", "  sel:\n    Hashes|contains: 'MD5=abc'\n  condition: sel\n"))
    assert r is None and "alias" in why


def test_negate_text():
    assert sigma._negate('$e.a = "x" nocase and ($e.b = 1 or net.ip_in_range_cidr($e.ip, "10.0.0.0/8"))') == \
        '($e.a != "x" nocase or ($e.b != 1 and not net.ip_in_range_cidr($e.ip, "10.0.0.0/8")))'


# ---------------------------------------------------------------- import details
def test_split_ignores_rules_inside_comments():
    text = "rule a {\n events:\n  $e.x = 1\n condition:\n  $e\n}\n/*\nrule old {\n}\n*/\n// rule older {\n"
    assert [n for n, _ in _split_rules(text)] == ["a"]


def test_git_import_reads_unusual_file_names(dehome, tmp_path):
    repo = tmp_path / "repo"
    (repo / "rules" / "x").mkdir(parents=True)
    (repo / "rules" / "x" / "ünïcode.yaral").write_text("rule u {\n events:\n  $e.x = 1\n condition:\n  $e\n}\n",
                                                        encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], check=True)
    dehome.run("import", "uni", f"file://{repo}", check=True)
    cfg = (dehome.environments / "uni" / "rule_config.yaml").read_text(encoding="utf-8")
    assert "rules/x/" in cfg and (dehome.environments / "uni" / "rules" / "u.yaral").exists()


def test_undated_template_entry_is_dropped():
    import datetime as dt
    from delib.facts import normalise_logbooks
    book = [{"date": None, "score": -1, "comment": ""}, {"date": dt.datetime(2026, 10, 6), "score": -1, "comment": "x"}]
    normalise_logbooks({"techniques": [{"detection": [{"score_logbook": book}]}]})
    assert all(e["date"] for e in book)
