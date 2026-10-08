"""Every place yadda depends on another tool's internals, checked against the installed (pinned) versions.
A failure here after `yadda setup --latest` is exactly what stops that command re-pinning."""
import pytest

from conftest import ROOT

pytestmark = pytest.mark.tools


@pytest.fixture(scope="module")
def results():
    if not (ROOT / "tools" / "attack-stix-data").exists():
        pytest.skip("third-party tools not installed (run: yadda setup)")
    from delib.doctor import checks
    return checks()


def test_every_contract_holds(results):
    bad = [f"{n}: {d}" for n, ok, d in results if not ok]
    assert not bad, "\n".join(bad)


def test_all_contracts_were_checked(results):
    assert len(results) >= 8          # ATT&CK, Content Manager, calculator, Sigma, ART, MISP, Attack Flow, TIE
