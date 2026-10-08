"""config - project paths, upstream repos and pinned commits, and the file helpers every module uses
(encoding-tolerant CSV/text reads, atomic writes)."""
from __future__ import annotations

import csv
import io
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


# The project folder (yadda.py, environments/, shared/, tools/). DE_HOME overrides it, e.g. for tests.
HOME = Path(os.environ.get("DE_HOME") or Path(__file__).resolve().parent.parent)


TOOLS = HOME / "tools"


SHARED = HOME / "shared"


ENVIRONMENTS = HOME / "environments"


STIX = TOOLS / "attack-stix-data"




CONTENT_MANAGER = TOOLS / "detection-rules" / "tools" / "content_manager"


DETECTED = 3  # latest detection score >= this counts as detected (see shared/score_definitions.md)


REPOS = {
    "detection-rules": "https://github.com/chronicle/detection-rules.git",
    "summiting-the-pyramid": "https://github.com/center-for-threat-informed-defense/summiting-the-pyramid.git",
    "sigma": "https://github.com/SigmaHQ/sigma.git",            # rule source for yadda sigma (candidates)
}


DCC_REPO = TOOLS / "summiting-the-pyramid"     # MITRE's Detection Coverage Calculator lives in its DCC folder


# tools.lock pins every upstream repo (git tools and raw data files) to a commit that passed `yadda doctor`.
# `yadda setup` installs exactly those; `yadda setup --latest` tries the newest and re-pins only if doctor passes.
LOCK = HOME / "tools.lock"
DATA_REPOS = {
    "attack-stix-data": "https://github.com/mitre-attack/attack-stix-data.git",
    "atomic-red-team": "https://github.com/redcanaryco/atomic-red-team.git",
    "misp-galaxy": "https://github.com/MISP/misp-galaxy.git",
    "attack-flow": "https://github.com/center-for-threat-informed-defense/attack-flow.git",          # yadda flows corpus
    "technique-inference-engine": "https://github.com/center-for-threat-informed-defense/technique-inference-engine.git",
}
MAIN_BRANCH = {"misp-galaxy", "attack-flow", "technique-inference-engine"}     # default branch "main", not "master"


def read_lock() -> dict[str, str]:
    """{repo name: commit sha} from tools.lock ('name sha  # comment' lines). Missing file -> {} (= latest)."""
    out = {}
    if LOCK.exists():
        for line in LOCK.read_text(encoding="utf-8").splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{40}", parts[1]):
                out[parts[0]] = parts[1]
    return out


def write_lock(pins: dict[str, str]) -> None:
    urls = {**REPOS, **DATA_REPOS}
    lines = ["# yadda tools.lock - upstream commits known to pass `yadda doctor`. Written by `yadda setup --latest`.",
             "# name  commit  # repository"]
    lines += [f"{n} {pins[n]}  # {urls.get(n, '')}" for n in sorted(pins, key=str.lower)]
    write_text(LOCK, "\n".join(lines) + "\n")


def download(url: str, dest: Path) -> None:
    """Fetch url into dest; a failed download leaves any existing file untouched."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=300) as r:
            data = r.read()
    except (urllib.error.URLError, OSError) as e:
        die(f"download failed: {url} ({e})")
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_bytes(dest, data)


def raw_url(repo: str, path: str, ref: str | None = None) -> str:
    """raw.githubusercontent.com URL for a file of a data repo, at the pinned commit (or `ref`)."""
    owner_repo = DATA_REPOS[repo].removeprefix("https://github.com/").removesuffix(".git")
    ref = ref or read_lock().get(repo) or ("main" if repo in MAIN_BRANCH else "master")
    return f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"


TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# ---------------------------------------------------------------- helpers
def out_dir(c: Path, sub: str = "") -> Path:
    """Where this run's outputs go: output/<environment>/<date>/[sub]. One folder per day is the history."""
    import datetime as _dt
    d = HOME / "output" / c.name / str(_dt.date.today()) / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


def die(msg: str) -> None:
    sys.exit(f"yadda: {msg}")


WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def valid_name(name: str) -> str:
    """An environment name is a folder directly under environments/: letters, digits, '.', '_', '-' (not first), no
    '..', no path separators, no Windows device names. Anything else could write outside environments/."""
    ok = (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name or "") and ".." not in name
          and not name.endswith(".") and name.split(".")[0].lower() not in WINDOWS_RESERVED
          and (ENVIRONMENTS / name).resolve().parent == ENVIRONMENTS.resolve())
    if not ok:
        die(f"'{name}' can't be an environment name - use letters, digits, '.', '_' or '-' (e.g. acme, acme-uk)")
    return name


def envdir(name: str) -> Path:
    valid_name(name)
    p = ENVIRONMENTS / name
    if not p.is_dir():
        die(f"no environment '{name}'. Known: {', '.join(environment_names()) or 'none'}  (create with: yadda new {name})")
    return p


def environment_names() -> list[str]:
    return sorted(p.name for p in ENVIRONMENTS.iterdir() if p.is_dir() and not p.name.startswith("_"))


def read_env(path: Path) -> dict:
    env = {}
    for line in read_text(path).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            env[k.strip()] = v
    return env


def secops_env(c: Path) -> dict:
    """Process environment for SecOps API calls: os.environ overlaid with environment.env. GOOGLE_APPLICATION_CREDENTIALS
    there can name a login file per environment (one Google account each); %VARS% and ~ are expanded."""
    env = {**os.environ, **read_env(c / "environment.env")}
    f = env.get("GOOGLE_APPLICATION_CREDENTIALS")
    if f:
        f = re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), f)     # Windows %VARS%, any OS
        f = os.path.expanduser(os.path.expandvars(f))
        if not Path(f).is_file():
            die(f"{c.name}: GOOGLE_APPLICATION_CREDENTIALS points to {f}, which doesn't exist. Log in for this "
                "environment first (docs/setup.md, step 5)")
        env["GOOGLE_APPLICATION_CREDENTIALS"] = f
    return env


def set_env(c: Path, key: str, value) -> None:
    """Set KEY=value in <environment>/environment.env, keeping every other line (comments included)."""
    f = c / "environment.env"
    lines = read_text(f).splitlines() if f.exists() else []
    out, done = [], False
    for line in lines:
        if re.match(rf"\s*{re.escape(key)}\s*=", line):
            if not done:
                out.append(f"{key}={value}")
                done = True
            continue
        out.append(line)
    if not done:
        out.append(f"{key}={value}")
    write_text(f, "\n".join(out) + "\n")


# ---------------------------------------------------------------- safe file reading and writing
# Analysts open and re-save these files in Excel and Notepad, and on Windows: expect BOMs, cp1252, UTF-16,
# semicolons and files left open. Every write goes to a temp file first, so a crash or Ctrl+C never leaves
# half a file behind.
def read_text(path: Path) -> str:
    """UTF-8 (with or without BOM), UTF-16 (BOM) or cp1252, whichever the bytes are."""
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def read_csv(path: Path) -> tuple[list[str], list[dict]]:
    """(header, rows) of a CSV, whatever its encoding or delimiter (comma, semicolon, tab). Blank lines skipped."""
    lines = read_text(path).splitlines()
    while lines and not lines[0].strip(",;\t "):           # leading blank (or delimiter-only) lines
        lines.pop(0)
    delim = None
    if lines and re.fullmatch(r"\s*sep=(.)\s*", lines[0], re.I):   # Excel's "sep=;" hint line
        delim = re.fullmatch(r"\s*sep=(.)\s*", lines[0], re.I).group(1)
        lines.pop(0)
    text = "\n".join(lines)
    first = lines[0] if lines else ""
    delim = delim or (max(",;\t", key=first.count) if first else ",")
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delim)
    rows = [r for r in reader if any((v or "").strip() for k, v in r.items() if k is not None)]
    return [h for h in (reader.fieldnames or [])], rows


def write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    write_bytes(path, text.encode(encoding))


def write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        die(f"can't write {path} - it is probably open in another program (Excel?). Close it and run again.")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def write_csv(path: Path, fields: list, rows: list[dict], encoding: str = "utf-8-sig") -> None:
    """Write rows with the given columns first; columns the rows carry beyond those are kept, not dropped."""
    extra = [k for r in rows for k in r if k not in fields]
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=list(fields) + list(dict.fromkeys(extra)), restval="", lineterminator="\r\n")
    w.writeheader()
    w.writerows(rows)
    write_text(path, out.getvalue(), encoding)


def write_rows(path: Path, header: list, rows: list, encoding: str = "utf-8-sig") -> None:
    """Write a header and list-shaped rows as CSV, atomically."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(header)
    w.writerows(rows)
    write_text(path, out.getvalue(), encoding)


def write_yaml(path: Path, data, y=None) -> None:
    """Round-trip YAML (ruamel) written atomically."""
    out = io.StringIO()
    (y or yaml_rt()).dump(data, out)
    write_text(path, out.getvalue())


def _rmtree(path: Path) -> None:
    """shutil.rmtree that also removes read-only files (git objects on Windows)."""
    import stat
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=onerror)


def run(args: list, cwd: Path | None = None, env: dict | None = None) -> None:
    r = subprocess.run([str(a) for a in args], cwd=cwd, env=env)
    if r.returncode:
        shown = [Path(str(a)).name if i == 0 else str(a).split("\n")[0][:60] for i, a in enumerate(args[:4])]
        die(f"command failed (exit {r.returncode}): {' '.join(shown)} ...")


def yaml_rt():
    from ruamel.yaml import YAML
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def yaml_dump_plain(doc: dict) -> str:
    import yaml as _y
    return _y.safe_dump(doc, sort_keys=False, allow_unicode=True)


def _pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "-"
