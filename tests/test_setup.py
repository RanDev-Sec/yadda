"""yadda setup / tools.lock: pinned installs, and --latest only re-pinning when every doctor check passes."""
import pytest

from delib import commands, config, upstream

OLD = {n: "a" * 40 for n in {**config.REPOS, **config.DATA_REPOS}}
NEW = {n: "b" * 40 for n in OLD}


@pytest.fixture
def lockhome(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LOCK", tmp_path / "tools.lock")
    monkeypatch.setattr(commands, "REQ_LOCK", tmp_path / "requirements.lock")
    config.write_lock(OLD)
    installed = []
    monkeypatch.setattr(commands, "_install", lambda pins: installed.append(dict(pins)))
    monkeypatch.setattr(commands, "_tool_requirements", lambda: None)
    monkeypatch.setattr(commands, "_pip", lambda *a: None)
    monkeypatch.setattr(commands, "_freeze_requirements",
                        lambda: (tmp_path / "requirements.lock").write_text("x==1\n"))
    monkeypatch.setattr(upstream, "latest_sha", lambda url: "b" * 40)
    return installed


def test_lock_round_trip(lockhome):
    assert config.read_lock() == OLD


def test_raw_urls_use_the_pinned_commit(lockhome):
    assert "/" + "a" * 40 + "/clusters/x.json" in config.raw_url("misp-galaxy", "clusters/x.json")


def test_latest_keeps_old_pins_when_a_check_fails(lockhome, monkeypatch):
    import delib.doctor
    monkeypatch.setattr(delib.doctor, "checks", lambda only=None: [("DeTT&CT `d` options", False, "missing -ft")])
    with pytest.raises(SystemExit):
        commands.cmd_setup(["--latest"])
    assert config.read_lock() == OLD                      # lock untouched
    assert lockhome[-1] == OLD                            # and the pinned versions were put back


def test_latest_repins_when_every_check_passes(lockhome, monkeypatch):
    import delib.doctor
    monkeypatch.setattr(delib.doctor, "checks", lambda only=None: [("x", True, "ok")])
    commands.cmd_setup(["--latest"])
    assert config.read_lock() == NEW
    assert commands.REQ_LOCK.read_text() == "x==1\n"


def test_plain_setup_installs_the_lock(lockhome):
    commands.cmd_setup([])
    assert lockhome == [OLD]


def test_latest_restores_lock_when_install_fails(lockhome, monkeypatch):
    import delib.doctor
    monkeypatch.setattr(delib.doctor, "checks", lambda only=None: [("x", True, "ok")])
    monkeypatch.setattr(commands, "_tool_requirements", lambda: (_ for _ in ()).throw(SystemExit("pip failed")))
    with pytest.raises(SystemExit):
        commands.cmd_setup(["--latest"])
    assert config.read_lock() == OLD and lockhome[-1] == OLD


def test_latest_without_a_lock_leaves_no_untested_lock(lockhome, monkeypatch):
    import delib.doctor
    config.LOCK.unlink()
    monkeypatch.setattr(delib.doctor, "checks", lambda only=None: [("x", False, "broken")])
    with pytest.raises(SystemExit, match="no pinned versions"):
        commands.cmd_setup(["--latest"])
    assert not config.LOCK.exists()


def test_latest_with_a_partial_lock_restores_without_crashing(lockhome, monkeypatch):
    import delib.doctor
    config.write_lock({"misp-galaxy": "a" * 40})
    monkeypatch.setattr(delib.doctor, "checks", lambda only=None: [("x", False, "broken")])
    with pytest.raises(SystemExit, match="not changed"):
        commands.cmd_setup(["--latest"])
    assert config.read_lock() == {"misp-galaxy": "a" * 40}
    assert lockhome[-1]["misp-galaxy"] == "a" * 40 and lockhome[-1]["sigma"] == "b" * 40


def test_environment_login_file_from_environment_env(tmp_path, monkeypatch):
    """environment.env can name its own Google login file; %VARS% expand; a missing file stops with a clear message."""
    import pytest
    from delib.config import secops_env
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    login = tmp_path / ".gcloud-acme" / "application_default_credentials.json"
    login.parent.mkdir()
    login.write_text("{}", encoding="utf-8")
    c = tmp_path / "acme"
    c.mkdir()
    (c / "environment.env").write_text("GOOGLE_APPLICATION_CREDENTIALS=%USERPROFILE%/.gcloud-acme/application_default_credentials.json\n")
    assert secops_env(c)["GOOGLE_APPLICATION_CREDENTIALS"] == str(login).replace("\\", "/") or \
        secops_env(c)["GOOGLE_APPLICATION_CREDENTIALS"].endswith("application_default_credentials.json")
    (c / "environment.env").write_text("GOOGLE_APPLICATION_CREDENTIALS=%USERPROFILE%/missing.json\n")
    with pytest.raises(SystemExit, match="Log in for this environment"):
        secops_env(c)
