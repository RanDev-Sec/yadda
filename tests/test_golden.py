"""Whole-pipeline regression test on the fictional 'acme' environment.

Compares every command's output and the key result files with tests/golden/acme. Needs the third-party tools
installed by `yadda setup` (ATT&CK data, MITRE calculator); skipped when they're missing.
If a change is meant to alter results: python tests/characterize.py --update, then review `git diff tests/golden`.
"""
from __future__ import annotations

import difflib
from pathlib import Path

import pytest

from characterize import ROOT, run

GOLDEN = Path(__file__).resolve().parent / "golden" / "acme"
NEEDS = [ROOT / "tools" / "attack-stix-data", 
         ROOT / "tools" / "summiting-the-pyramid"]


@pytest.fixture(scope="module")
def last_run(tmp_path_factory):
    if not all(p.exists() for p in NEEDS):
        pytest.skip("third-party tools not installed (run: yadda setup)")
    out = tmp_path_factory.mktemp("golden") / "acme"
    run(out)
    return out


def files():
    return sorted(p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file())


@pytest.mark.tools
@pytest.mark.parametrize("name", files())
def test_matches_golden(last_run, name):
    want = (GOLDEN / name).read_text(encoding="utf-8").splitlines()
    got_path = last_run / name
    assert got_path.exists(), f"{name} was not produced"
    got = got_path.read_text(encoding="utf-8").splitlines()
    if want != got:
        diff = "\n".join(difflib.unified_diff(want, got, "golden/" + name, "this run/" + name, lineterm="", n=1))
        pytest.fail(f"{name} differs from golden:\n{diff[:4000]}")


@pytest.mark.tools
def test_no_unexpected_outputs(last_run):
    extra = sorted(p.relative_to(last_run).as_posix() for p in last_run.rglob("*") if p.is_file()) 
    assert set(extra) == set(files())
