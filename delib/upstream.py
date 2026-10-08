"""upstream - installs the third-party repos yadda uses at the commits pinned in tools.lock, and locates MITRE's
Detection Coverage Calculator inside its repo."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from delib.config import CONTENT_MANAGER, DCC_REPO, REPOS, TOOLS, _rmtree, die, read_lock, run, write_lock


# ---------------------------------------------------------------- installing pinned tools
def _swap_in(new: Path, final: Path) -> None:
    """Replace an installed tool only once the new copy is complete, so a failed download keeps the old one."""
    old = final.with_name(final.name + ".old")
    if old.exists():
        _rmtree(old)
    if final.exists():
        final.rename(old)
    new.rename(final)
    if old.exists():
        _rmtree(old)


def latest_sha(url: str) -> str:
    """Commit at the tip of the repo's default branch."""
    try:
        out = subprocess.check_output(["git", "ls-remote", url, "HEAD"], text=True, timeout=120)
    except (subprocess.SubprocessError, OSError) as e:
        die(f"can't reach {url} ({e})")
    if not out.split():
        die(f"{url} returned no HEAD commit")
    return out.split()[0]


def installed_sha(d: Path) -> str | None:
    try:
        return subprocess.check_output(["git", "-C", str(d), "rev-parse", "HEAD"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except (subprocess.SubprocessError, OSError):
        return None


def tool_versions() -> str:
    """'detection-rules 234e922, sigma 8a48134, ...' - the installed commit of each tool, for reports and bug reports."""
    return ", ".join(f"{n} {(installed_sha(TOOLS / n) or 'not installed')[:7]}" for n in REPOS)


def _git_at(url: str, sha: str, dest: Path, checkout: bool = True) -> None:
    """Shallow fetch of exactly one commit into dest (an empty folder)."""
    if dest.exists():
        _rmtree(dest)
    dest.mkdir(parents=True)
    g = ["git", "-C", dest]
    run([*g, "init", "--quiet"])
    run([*g, "config", "core.longpaths", "true"])          # Windows: some repos have paths over 260 characters
    run([*g, "remote", "add", "origin", url])
    run([*g, "fetch", "--quiet", "--depth", "1", "origin", sha])
    if checkout:
        run([*g, "-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"])
    else:
        run([*g, "update-ref", "HEAD", "FETCH_HEAD"])      # HEAD = the commit, nothing written to disk


def _complete(d: Path, name: str) -> bool:
    """A checked-out tool with no files missing (an earlier checkout can stop part-way, e.g. on a too-long path)."""
    if name == "detection-rules":                 # fetched without checkout: only the Content Manager files exist
        return True
    r = subprocess.run(["git", "-C", str(d), "status", "--porcelain", "--untracked-files=no"],
                       capture_output=True, text=True)
    return r.returncode == 0 and not r.stdout.strip()


def fetch_tool(name: str, sha: str) -> None:
    """Install repo `name` at commit `sha`. Fetched into <name>.new and swapped in only when complete."""
    final = TOOLS / name
    if installed_sha(final) == sha and (name != "detection-rules" or CONTENT_MANAGER.exists()) and _complete(final, name):
        print(f"{name} already at {sha[:12]}")
        return
    print(f"fetching {name} at {sha[:12]} ...", flush=True)
    new = final.with_name(name + ".new")
    try:
        if name == "detection-rules":
            _fetch_content_manager(new, sha)
        else:
            _git_at(REPOS[name], sha, new)
    except BaseException:
        if new.exists():
            _rmtree(new)                                         # the installed copy is untouched
        raise
    _swap_in(new, final)


def _fetch_content_manager(d: Path, sha: str) -> None:
    """Google's repo contains rule files whose names Windows cannot store ('?'), and git on Windows
    rejects any checkout of it, even a sparse one. So fetch without a checkout and write only the
    tools/content_manager files."""
    _git_at(REPOS["detection-rules"], sha, d, checkout=False)
    files = subprocess.check_output(["git", "-C", str(d), "ls-tree", "-r", "--name-only", "HEAD",
                                     "--", "tools/content_manager"], text=True).split("\n")
    files = [f for f in files if f]
    for f in files:
        out = d / f
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(subprocess.check_output(["git", "-C", str(d), "show", f"HEAD:{f}"]))
    print(f"  {len(files)} Content Manager files")


def _fetch_dcc(sha: str | None = None) -> None:
    """MITRE's Summiting the Pyramid repo, which holds the Detection Coverage Calculator and its reference
    workbooks. Nothing in it is modified. Default: the commit pinned in tools.lock."""
    sha = sha or read_lock().get("summiting-the-pyramid") or latest_sha(REPOS["summiting-the-pyramid"])
    fetch_tool("summiting-the-pyramid", sha)
    run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-q", "pyyaml", "openpyxl"])
    d = _dcc()
    print(f"  calculator: {d['script'].relative_to(TOOLS)}  ({d['version']})")


def update_dcc() -> None:
    """Newest calculator; kept and pinned in tools.lock only if the doctor's calculator check passes on it."""
    from delib.doctor import checks
    name = "summiting-the-pyramid"
    pins = read_lock()
    old, new = pins.get(name), latest_sha(REPOS[name])
    if new == old and installed_sha(DCC_REPO) == new:
        print(f"calculator already at the latest commit ({new[:12]})")
        return
    try:
        _fetch_dcc(new)
        res = checks(only="MITRE Detection Coverage Calculator")
    except SystemExit as e:
        res = [("", False, str(e.code))]
    if not (res and res[0][1]):
        print(f"  FAIL  {res[0][2] if res else 'calculator check missing'}")
        if old:
            print(f"putting the pinned calculator ({old[:12]}) back ...")
            _fetch_dcc(old)
            die("the latest calculator doesn't work the way yadda uses it, so tools.lock was not changed")
        die("the latest calculator doesn't work the way yadda uses it, and tools.lock has no earlier version to go back "
            "to - get tools.lock from the yadda repository and run `yadda setup`")
    pins[name] = new
    write_lock(pins)
    print(f"calculator check passed - tools.lock now pins {name} at {new[:12]}")


def _dcc() -> dict:
    """Locate the installed calculator and its reference workbooks by name, wherever MITRE put them in the repo."""
    if not DCC_REPO.exists():
        die("MITRE Detection Coverage Calculator not installed - run: yadda setup   (or: yadda robustness --update)")
    script = next(iter(sorted(DCC_REPO.rglob("coveragecalculator.py"))), None)
    if script is None:
        die(f"coveragecalculator.py not found under {DCC_REPO} - MITRE may have renamed it; check the repo README")
    find = lambda pat: next(iter(sorted(script.parent.glob(pat))), None)
    try:
        version = subprocess.check_output(["git", "-C", str(DCC_REPO), "log", "-1", "--format=%h %cs"], text=True).strip()
    except Exception:
        version = "unknown version"
    return {"script": script, "scoring": find("scoring_dictionary*.xlsx"), "mappings": find("mappings*.xlsx"),
            "catalog": find("implementation_catalog*.xlsx"), "version": version}


