"""The one YARA-L parser: scope (event/log types, event IDs) read from live logic only."""
from pathlib import Path

from delib.yaral import scope

RULES = Path(__file__).resolve().parent / "fixtures" / "acme" / "rules"


def test_comment_and_negation_do_not_count():
    s = scope((RULES / "r07_comment_and_negation.yaral").read_text(encoding="utf-8"))
    assert s["event_types"] == {"PROCESS_LAUNCH", "PROCESS_OPEN"}


def test_or_branches_and_log_types():
    s = scope((RULES / "r03_portproxy.yaral").read_text(encoding="utf-8"))
    assert s["event_types"] == {"PROCESS_LAUNCH", "REGISTRY_CREATION", "REGISTRY_MODIFICATION"}
    s = scope((RULES / "r05_okta_push_spam.yaral").read_text(encoding="utf-8"))
    assert s["log_types"] == {"OKTA"} and s["event_types"] == {"USER_LOGIN"}


def test_product_event_ids():
    s = scope((RULES / "r04_service_list.yaral").read_text(encoding="utf-8"))
    assert s["product_event_types"] == {"7045"}
    s = scope((RULES / "r06_github_2fa_disabled.yaral").read_text(encoding="utf-8"))
    assert s["event_types"] == set() and s["product_event_types"] == {"org.disable_two_factor_requirement"}


def test_meta_and_outcome_are_ignored():
    text = '''rule x {
  meta:
    note = "$e.metadata.event_type = \\"FILE_DELETION\\""
  events:
    $e.metadata.event_type = "USER_LOGIN"
  outcome:
    $o = if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0)
  condition:
    $e
}'''
    assert scope(text)["event_types"] == {"USER_LOGIN"}
