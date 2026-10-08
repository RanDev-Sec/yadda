import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))


def pytest_configure(config):
    config.addinivalue_line("markers", "tools: needs the third-party tools installed by yadda setup")


import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402

ROOT = HERE.parent


class DeHome:
    """A throwaway project folder: real tools/ (linked), copied shared/, empty environments/. Commands run in a
    subprocess with DE_HOME pointing here, so tests can never touch the real environments."""

    def __init__(self, path):
        self.path = path
        self.environments = path / "environments"

    def run(self, *args, check=False):
        env = {**os.environ, "DE_HOME": str(self.path), "PYTHONUTF8": "1"}
        p = subprocess.run([sys.executable, str(ROOT / "yadda.py"), *map(str, args)], cwd=self.path, env=env,
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        p.out = p.stdout + p.stderr
        if check and p.returncode != 0:
            raise AssertionError(f"yadda {' '.join(map(str, args))} failed:\n{p.out[-3000:]}")
        return p

    def install(self, fixture="acme", name="acme"):
        from fixture_install import install
        return install(fixture, name, environments=self.environments)


def make_home(path):
    if not (ROOT / "tools" / "attack-stix-data").exists():
        pytest.skip("third-party tools not installed (run: yadda setup)")
    (path / "environments").mkdir()
    shutil.copytree(ROOT / "environments" / "_template", path / "environments" / "_template")
    shutil.copytree(ROOT / "shared", path / "shared")
    try:
        (path / "tools").symlink_to(ROOT / "tools", target_is_directory=True)
    except OSError:
        pytest.skip("cannot link tools/ here (Windows without symlink rights)")
    return DeHome(path)


@pytest.fixture
def dehome(tmp_path):
    return make_home(tmp_path)


@pytest.fixture(scope="module")
def acme(tmp_path_factory):
    """The acme fixture run through the whole pipeline once per test module: sync, data, evidence, review,
    robustness. Returns (DeHome, environment folder)."""
    h = make_home(tmp_path_factory.mktemp("home"))
    c = h.install()
    for a in (("sync", "acme"), ("data", "acme", c / "inputs" / "inventory.csv"),
              ("evidence", "acme", c / "inputs" / "rule_health.csv", c / "inputs" / "rule_fp.csv"), ("review", "acme"),
              ("robustness", "acme")):
        h.run(*a, check=True)
    return h, c


def in_home(h, code: str):
    """Run python code with the yadda package against a DeHome; returns stdout (use print(json.dumps(...)))."""
    env = {**os.environ, "DE_HOME": str(h.path), "PYTHONUTF8": "1"}
    p = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n" % str(ROOT) + code],
                       cwd=h.path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    if p.returncode:
        raise AssertionError(p.stderr[-3000:])
    return p.stdout
