"""commands - the setup, environment, rule and score commands, and the `yadda help` text."""
from __future__ import annotations

import datetime as dt
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from delib import config
from delib import inputs
from delib.config import secops_env, _rmtree, CONTENT_MANAGER, envdir, environment_names, ENVIRONMENTS, DATA_REPOS, die, download, HOME, raw_url, read_csv, read_lock, read_text, REPOS, run, set_env, STIX, TOOLS, valid_name, write_lock, write_text, write_yaml, yaml_rt
from delib.upstream import fetch_tool
from delib.telemetry import _mapping, _read_export, _read_inventory, _row_dcs, cmd_mapping, present
from delib.facts import NEW_TECHNIQUES_FILE, sync_detections, _enabled_rules, _report_tag_problems, _set_score, _summary, base_name, fp_pct, load_techniques, normalise_logbooks, read_fp, read_health, thresholds
from delib.validation import ART_PLATFORMS, _art_index, cmd_atomics, cmd_test
from delib.robustness import cmd_robustness
from delib.actors import _misp, cmd_actors
from delib.run import cmd_run
from delib.priorities import cmd_priorities
from delib.analysis import cmd_check, cmd_metrics, cmd_review, cmd_rules
from delib.dashboard import cmd_dashboard
from delib.doctor import cmd_doctor
from delib.sigma import cmd_sigma


REQ_LOCK = HOME / "requirements.lock"
DEV_ONLY = {"pytest", "ruff", "iniconfig", "pluggy"}       # requirements-dev.txt and what only they pull in


def _pip(*args) -> None:
    run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--progress-bar", "on", *args])


def _tool_requirements() -> None:
    for req in [CONTENT_MANAGER / "requirements.txt"]:
        print(f"installing Python packages for {req.parent.name} (can take a few minutes) ...", flush=True)
        _pip("-r", req)
    _pip("pyyaml", "openpyxl")                                   # MITRE's calculator
    _pip("pysigma-backend-secops")                               # yadda sigma (pulls in pySigma)
    _pip("numpy")                                                # TIE inference


def _freeze_requirements() -> None:
    out = subprocess.check_output([sys.executable, "-m", "pip", "freeze", "--disable-pip-version-check",
                                   "--exclude-editable"], text=True)
    keep = [line for line in out.splitlines()
            if line and "==" in line and line.split("==")[0].lower().replace("_", "-") not in DEV_ONLY]
    write_text(REQ_LOCK, "# Python packages known to work with the tool commits in tools.lock. "
                         "Written by `yadda setup --latest`.\n" + "\n".join(keep) + "\n")


def _attack_flow_corpus(sha: str) -> None:
    """Fetch the Attack Flow corpus (corpus/*.afb) at `sha`, without a checkout."""
    from delib.upstream import _git_at, _swap_in
    final = TOOLS / "attack-flow"
    if (final / "COMMIT").exists() and (final / "COMMIT").read_text().strip() == sha:
        print(f"Attack Flow corpus already at {sha[:12]}")
        return
    new = final.with_name("attack-flow.new")
    print(f"fetching Attack Flow corpus at {sha[:12]} ...", flush=True)
    try:
        _git_at(DATA_REPOS["attack-flow"], sha, new, checkout=False)
        names = subprocess.check_output(["git", "-C", str(new), "ls-tree", "-z", "--name-only", "HEAD", "corpus/"])
        files = [f for f in names.decode("utf-8").split("\0") if f.endswith(".afb")]
        for f in files:
            out = new / f
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(subprocess.check_output(["git", "-C", str(new), "show", f"HEAD:{f}"]))
        _rmtree(new / ".git")
        (new / "COMMIT").write_text(sha + "\n")
    except BaseException:
        if new.exists():
            _rmtree(new)
        raise
    _swap_in(new, final)
    print(f"  {len(files)} flows")


def _install(pins: dict) -> None:
    """Install every upstream repo at the commit in `pins`. tools.lock must already hold `pins`: the data downloads
    read it."""
    TOOLS.mkdir(exist_ok=True)
    for name in REPOS:
        fetch_tool(name, pins[name])
    import json
    marker = TOOLS / "data_pins.json"                          # data files already downloaded, by pinned commit
    try:
        have = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else {}
    except ValueError:
        have = {}

    def fresh(repo, files):
        """True when these files exist and were downloaded at the pinned commit."""
        if have.get(repo) == pins.get(repo) and all(Path(f).exists() for f in files):
            print(f"{repo} data already at {pins[repo][:12]}")
            return True
        return False

    def done(repo):
        have[repo] = pins.get(repo)
        write_text(marker, json.dumps(have, indent=1))

    stix_files = [STIX / d / f"{d}.json" for d in ("enterprise-attack", "ics-attack", "mobile-attack")] + [STIX / "index.json"]
    if not fresh("attack-stix-data", stix_files):
        for d in ("enterprise-attack", "ics-attack", "mobile-attack"):
            print(f"downloading ATT&CK {d} ...", flush=True)
            download(raw_url("attack-stix-data", f"{d}/{d}.json"), STIX / d / f"{d}.json")
        # MITRE's index of the ATT&CK collections, kept next to the data.
        download(raw_url("attack-stix-data", "index.json"), STIX / "index.json")
        done("attack-stix-data")
    if not fresh("atomic-red-team", [TOOLS / "art" / "windows-index.csv"]):
        _art_index(set(ART_PLATFORMS), refresh=True)              # used by yadda atomics / yadda test
        done("atomic-red-team")
    if not fresh("misp-galaxy", [TOOLS / "misp" / f"{n}.json" for n in ("threat-actor", "country", "region")]):
        for name in ("threat-actor", "country", "region"):       # used by yadda actors
            (TOOLS / "misp" / f"{name}.json").unlink(missing_ok=True)
            _misp(name)
        done("misp-galaxy")
    if not fresh("technique-inference-engine", [TOOLS / "tie" / "app.trained.model.zip"]):
        print("downloading MITRE CTID Technique Inference Engine model ...", flush=True)
        download(raw_url("technique-inference-engine", "src/tie-web-interface/public/app.trained.model.zip"),
                 TOOLS / "tie" / "app.trained.model.zip")
        done("technique-inference-engine")
    _attack_flow_corpus(pins["attack-flow"])


def cmd_setup(args):
    """yadda setup [--latest | --check]  - install the tools and data at the versions pinned in tools.lock.
    --latest: try the newest version of everything; keep it (and re-pin) only if every `yadda doctor` check passes."""
    from delib.doctor import checks
    from delib.upstream import latest_sha
    if "--check" in args:
        return cmd_doctor([])
    pins = read_lock()
    urls = {**REPOS, **DATA_REPOS}
    if "--latest" not in args:
        missing = [n for n in urls if n not in pins]
        if missing:
            print(f"tools.lock has no pin for {', '.join(missing)} - using their latest commit")
            pins.update({n: latest_sha(urls[n]) for n in missing})
            write_lock(pins)
        _install(pins)
        if REQ_LOCK.exists():
            print("installing pinned Python packages (requirements.lock) ...", flush=True)
            _pip("-r", REQ_LOCK)
        else:
            _tool_requirements()
        print(f"setup done ({attack_version_text()}). `yadda doctor` checks the tools work the way yadda uses them.")
        return

    old, had_lock = dict(pins), config.LOCK.exists()
    new = {n: latest_sha(u) for n, u in urls.items()}
    changed = {n for n in new if new[n] != old.get(n)}
    if not changed:
        print("everything is already at the latest commit")
    for n in sorted(changed, key=str.lower):
        print(f"  {n}: {old.get(n, 'none')[:12]} -> {new[n][:12]}")
    try:
        write_lock(new)                                          # the data downloads read the lock
        _install(new)
        _tool_requirements()
        res = checks()
        bad = [(n, d) for n, ok, d in res if not ok]
    except SystemExit as e:                                      # a download, git or pip step failed
        res, bad = [], [("installing the latest versions", str(e.code))]
    if bad:
        for n, d in bad:
            print(f"  FAIL  {n}: {d}")
        if had_lock:
            write_lock(old)
        else:
            config.LOCK.unlink(missing_ok=True)
        if old:
            back = {**new, **old}                                # repos the old lock didn't pin stay at latest
            print("putting the pinned versions back ...", flush=True)
            _install(back)
            if REQ_LOCK.exists():
                _pip("-r", REQ_LOCK)
            msg = "tools.lock was not changed"
        else:
            msg = "there were no pinned versions to go back to (no tools.lock); the latest ones are installed but unpinned"
        die(f"the latest versions don't work with yadda (above), so {msg}. "
            "Keep using the pinned versions, or adapt yadda to the new ones")
    _freeze_requirements()
    print(f"all {len(res)} checks passed - tools.lock and requirements.lock updated ({attack_version_text()})")


def attack_version_text() -> str:
    from delib.attack import attack_version
    try:
        return f"ATT&CK {attack_version()}"
    except Exception:  # noqa: BLE001 - informational only
        return "ATT&CK version unknown"


def cmd_new(args):
    """yadda new <environment>  - create an environment folder from environments/_template."""
    if not args:
        die("usage: yadda new <environment>")
    dst = ENVIRONMENTS / valid_name(args[0])
    clash = [n for n in environment_names() if n.casefold() == args[0].casefold() and n != args[0]]
    if clash:
        die(f"environment '{clash[0]}' already exists (Windows treats '{args[0]}' as the same folder)")
    if dst.exists():
        die(f"{dst} already exists")
    shutil.copytree(ENVIRONMENTS / "_template", dst)
    print(f"created {dst}\nnext: edit {dst / 'environment.env'}, then: yadda pull {args[0]}")


def cmd_pull(args):
    """yadda pull <environment>  - pull deployed rules from the environment's SecOps, then sync."""
    if not args:
        die("usage: yadda pull <environment>")
    c = envdir(args[0])
    env = secops_env(c)                 # the environment's own Google login, when environment.env names one
    # Content Manager always reads/writes its own rules folder: empty it so environments never mix.
    tool_rules = CONTENT_MANAGER / "rules"
    shutil.rmtree(tool_rules, ignore_errors=True)
    tool_rules.mkdir()
    (CONTENT_MANAGER / "rule_config.yaml").write_text("")
    # SecOps allows two rules with the same name (often an archived copy plus the live one);
    # Content Manager refuses that because it saves rules as <name>.yaral. Before its check runs,
    # give duplicate-named rules a unique name: <name>__<rule id>. Nothing changes in SecOps.
    runner = (
        "import collections, runpy, sys\n"
        "from content_manager.rules import Rules\n"
        "_orig = Rules.parse_rules\n"
        "def _parse(rules):\n"
        "    parsed = _orig(rules=rules)\n"
        "    n = collections.Counter(r.name.lower() for r in parsed)\n"
        "    for r in parsed:\n"
        "        if n[r.name.lower()] > 1:\n"
        "            print(f'duplicate rule name {r.name}: saved as {r.name}__{r.id}', flush=True)\n"
        "            r.name = f'{r.name}__{r.id}'\n"
        "    return parsed\n"
        "Rules.parse_rules = staticmethod(_parse)\n"
        "sys.argv = ['content_manager', 'rules', 'get']\n"
        "runpy.run_module('content_manager', run_name='__main__', alter_sys=True)\n"
    )
    run([sys.executable, "-c", runner], cwd=CONTENT_MANAGER, env=env)
    pulled = list(tool_rules.glob("*.yaral"))
    if not pulled:
        die("the pull returned no rules - the environment's existing rules were left as they are. "
            "Check environment.env and your gcloud login")
    if (c / "rules").exists():
        _rmtree(c / "rules")
    shutil.copytree(tool_rules, c / "rules")
    shutil.copy(CONTENT_MANAGER / "rule_config.yaml", c / "rule_config.yaml")
    print(f"pulled {len(list((c / 'rules').glob('*.yaral')))} rules")
    cmd_sync(args)


def cmd_sync(args):
    """yadda sync <environment>  - write enabled rules into techniques.yaml (new rules get score 1)."""
    if not args:
        die("usage: yadda sync <environment>")
    c = envdir(args[0])
    tagged, untagged = _enabled_rules(c)
    rules = tagged
    f = c / "techniques.yaml"
    y = yaml_rt()
    data = y.load(read_text(f)) if f.exists() else None
    if not data:
        data = dict(NEW_TECHNIQUES_FILE, name=c.name, techniques=[])
    normalise_logbooks(data)
    sync_detections(data, {name: r["techniques"] for name, r in tagged.items()})
    write_yaml(f, data, y)
    print(f"{c.name}: {len(rules)} enabled rules mapped to techniques.yaml")
    _report_tag_problems()
    if untagged:
        print(f"  {len(untagged)} enabled rules have NO usable ATT&CK technique in meta (invisible in coverage):")
        for n in untagged:
            print("   -", n)


def cmd_data(args):
    """Check the telemetry inventory and list what it can't map. Uses the newest inventory in inputs/, or the file
    given (which is then added to inputs/)."""
    if not args:
        die("usage: yadda data <environment> [<inventory.csv>]")
    c = envdir(args[0])
    src = Path(args[1]) if len(args) > 1 else inputs.current(c, "inventory")
    if src is None:
        print(f"{c.name}: no telemetry inventory in {inputs.folder(c)} - skipping data (telemetry shows as not seen)")
        return
    if not src.is_file():
        die(f"not found: {src}")
    inventory = _read_inventory(src)                   # dies on a bad export before anything is used
    if not inventory:
        die(f"{src.name}: no data rows - is it the export of telemetry_inventory.yaral? Fix or remove it")
    if len(args) > 1:
        inputs.add(c, src)
    mapping = _mapping()
    products, unmapped = defaultdict(set), Counter()
    for r in present(inventory)["rows"]:
        dcs = _row_dcs(r, mapping)
        if not dcs:
            unmapped[(r["log_type"], r["event_type"])] += r["events"]
        for dc in dcs:
            products[dc].add(r["log_type"])
    print(f"{c.name}: {len(products)} data components from {len({l for v in products.values() for l in v})} log types")
    if unmapped:
        print("  log type / event type pairs with no mapping (add rows to shared/udm_event_type_to_data_component.csv;"
              " the log_type and product_event_type columns can narrow a row to one product or event ID):")
        for (lt, et), n in unmapped.most_common(25):
            print(f"   - {lt} {et} ({n:,} events)")
        if len(unmapped) > 25:
            print(f"   ... and {len(unmapped) - 25} more")


def cmd_score(args):
    """yadda score <environment> <technique> <score> "<evidence>"  - record a detection score (dated)."""
    if len(args) < 4:
        die('usage: yadda score <environment> <T1234[.001]> <-1..5> "<evidence, e.g. 4/9 atomics passed 2026-10-05>"')
    c, tid, score, comment = envdir(args[0]), args[1].upper(), int(args[2]), " ".join(args[3:])
    if not -1 <= score <= 5:
        die("score must be -1..5 (see shared/score_definitions.md)")
    f = c / "techniques.yaml"
    if not f.exists():
        die(f"no techniques.yaml for {c.name} - run: yadda run {c.name}")
    y = yaml_rt()
    data = y.load(read_text(f))
    tech = _set_score(data, tid, score, comment)
    write_yaml(f, data, y)
    print(f"{c.name} {tid} {tech['technique_name']}: score {score} - {comment}")


EXPORTS = {"rule_health": "rule_health.csv", "rule_fp": "rule_fp.csv", "rule_logtypes": "rule_logtypes.csv"}
LOGTYPE_COLUMNS = {"name": ("rule_name", "display_name"), "lt": ("log_type",),
                   "n": ("detection_count", "count", "detections")}


def _export_kind(path: Path) -> str:
    """Which rule export a CSV is, from its columns (so the files can be given in any order)."""
    k = inputs.kind_of(path)
    if k not in EXPORTS:
        die(f"{path.name}: not a rule_health, rule_fp or rule_logtypes export")
    return k


def cmd_evidence(args):
    """yadda evidence <environment> <exports...> [--days 90] [--fp-max 50] [--min-cases 5]"""
    opts, given, rest = {"--days": 90, "--fp-max": 50, "--min-cases": 5}, {}, []
    it = iter(args)
    for a in it:
        if a in opts:
            v = next(it, "")
            if not v.isdigit():
                die(f"{a} needs a whole number, e.g. {a} {opts[a]}")
            given[a] = int(v)
        else:
            rest.append(a)
    if not rest:
        die("usage: yadda evidence <environment> [<export.csv> ...] [--days 90] [--fp-max 50] [--min-cases 5]")
    c = envdir(rest[0])
    given_files = {}
    for a in rest[1:]:
        src = Path(a)
        if not src.is_file():
            die(f"not found: {src}")
        kind = inputs.kind_of(src)
        if kind not in EXPORTS:
            die(f"{src.name}: not a rule_health, rule_fp or rule_logtypes export")
        if kind in given_files:
            die(f"{src.name} and {given_files[kind].name} are both {kind} exports - give one of each")
        given_files[kind] = src
    # An export you didn't give: the newest of its kind in inputs/.
    files = {k: given_files.get(k) or inputs.current(c, k) for k in EXPORTS}
    health_csv, fp_csv, lt_csv = files["rule_health"], files["rule_fp"], files["rule_logtypes"]
    if health_csv is None:
        print(f"{c.name}: no rule health export in {inputs.folder(c)} - skipping evidence (rules stay Unverified)")
        return
    if lt_csv is not None and "rule_logtypes" in given_files:
        rows = _read_export(lt_csv, LOGTYPE_COLUMNS)         # dies on a bad export before anything is replaced
        if not rows:
            die(f"{lt_csv.name}: no data rows - is it the export of rule_logtypes.yaral? Nothing was changed")
    # Options given here are saved in environment.env, so the dashboard, review and rules views judge "noisy" and
    # "recent" the same way the scores were set.
    th = thresholds(c)
    days = given.get("--days", th["days"])
    fp_max = given.get("--fp-max", th["fp_max"])
    min_cases = given.get("--min-cases", th["min_cases"])
    today = dt.date.today()

    tagged, _ = _enabled_rules(c)
    health = read_health(health_csv, {n: r["id"] for n, r in tagged.items()})
    if tagged and not health:
        die(f"{health_csv.name}: no rows for any of {c.name}'s {len(tagged)} enabled rules (empty export, or another "
            "environment's?). Nothing was changed")
    # A date format we can't read would silently turn every rule into "never fired" and downgrade scores.
    dated = [h for h in health.values() if str(h["raw"]).strip() not in ("", "0", "0.0")]
    unreadable = [h["raw"] for h in dated if h["last"] is None]
    if dated and len(unreadable) > len(dated) / 2:
        die(f"{health_csv.name}: can't read the detection dates (e.g. {', '.join(map(repr, unreadable[:3]))}). "
            "Export them as epoch seconds or YYYY-MM-DD; nothing was changed")
    fp = read_fp(fp_csv) if fp_csv else {}
    if fp_csv and "reason" not in {h.strip().lstrip("$").lower() for h in read_csv(fp_csv)[0] if h}:
        print(f"note: {fp_csv.name} has no reason column, so it counts alerts, not cases. For case-based numbers, "
              "run shared/queries/rule_fp_rate.yaral in SecOps and export again.")
    for key, env_key in (("--days", "EVIDENCE_DAYS"), ("--fp-max", "FP_MAX"), ("--min-cases", "MIN_CASES")):
        if key in given:
            set_env(c, env_key, given[key])
    for src in given_files.values():                        # checked: now the newest of its kind in inputs/
        inputs.add(c, src)

    # score each rule, then each technique takes its best rule
    rule_eval = {}
    shared = Counter(base_name(n) for n in list(tagged) + list(_enabled_rules(c)[1]))
    for name in tagged:
        h = health.get(name)
        if h is None:
            rule_eval[name] = (1, "not in rule health export")
            continue
        if h["last"] is None:
            rule_eval[name] = (1, f"{h['count']} detections but the export has no detection time" if h["count"]
                               else "never fired")
            continue
        age = (today - h["last"]).days
        # FP export has display names only: rules sharing one can't be told apart, so don't use it for them
        cases, bad, good = fp.get(base_name(name), (0, 0, 0)) if shared[base_name(name)] == 1 else (0, 0, 0)
        pct = fp_pct(bad, good)
        fp_txt = f", {cases} closed cases, {pct}% not malicious" if pct is not None else ""
        if age > days:
            rule_eval[name] = (1, f"last fired {h['last']} ({age} days ago)")
        elif pct is not None and bad + good >= min_cases and pct > fp_max:
            rule_eval[name] = (2, f"fired {h['last']}{fp_txt} - noisy")
        else:
            rule_eval[name] = (3, f"fired {h['last']}, {h['count']} detections{fp_txt}")
    tech_rules = defaultdict(list)
    for name, r in tagged.items():
        for t in r["techniques"]:
            tech_rules[t].append(name)

    f = c / "techniques.yaml"
    y = yaml_rt()
    data = y.load(read_text(f))
    current = load_techniques(c)
    changed, kept_validated, same = Counter(), 0, 0
    for tid, names in sorted(tech_rules.items()):
        best = max(names, key=lambda n: rule_eval[n][0])
        score, why = rule_eval[best]
        cur = current.get(tid, {}).get("score", -1)
        cur_comment = str(current.get(tid, {}).get("comment") or "")
        automatic = cur_comment.startswith(("yadda evidence:", "Auto added by yadda", "Auto added by Dettectinator",
                                            "Auto updated by Dettectinator")) \
            or cur_comment.strip() in ("", "-")
        if cur >= 4 or not automatic:    # validated, or a score a person recorded with yadda score: never overwrite
            kept_validated += 1
            continue
        if cur == score:
            same += 1
            continue
        _set_score(data, tid, score, f"yadda evidence: {best}: {why}" + (f" (+{len(names) - 1} more rules)" if len(names) > 1 else ""))
        changed[score] += 1
    write_yaml(f, data, y)

    rc = Counter(v[0] for v in rule_eval.values())
    print(f"{c.name}: {len(tagged)} enabled tagged rules - healthy {rc[3]}, noisy {rc[2]}, "
          f"never/not recently fired or missing {rc[1]}  (window {days} days, noisy = >{fp_max}% not malicious "
          f"over >= {min_cases} cases{'' if fp_csv else '; no FP export given'})")
    print(f"techniques: set to 3: {changed[3]}, set to 2: {changed[2]}, set to 1: {changed[1]}, "
          f"unchanged: {same}, left alone (set by hand or validated >= 4): {kept_validated}")
    missing = [n for n in tagged if n not in health]
    if missing:
        print(f"  {len(missing)} enabled rules not found in the health export (check the dashboard time range "
              f"is set to the maximum), e.g. {', '.join(missing[:5])}")


def cmd_status(_args):
    """yadda status  - one line per environment (techniques per state)."""
    names = environment_names()
    if not names:
        die("no environments yet - yadda new <environment>")
    cols = ["environment", "enabled_rules", "detected_ge3", "validated_ge4", "limited_2", "unverified_1", "data_no_rule",
            "last_change"]
    print("  ".join(f"{h:>13}" for h in cols))
    for n in names:
        s = _summary(ENVIRONMENTS / n)
        print("  ".join(f"{str(s[h]):>13}" for h in cols))


# ---------------------------------------------------------------- offline import
GIT_URL = re.compile(r"^(https?://|ssh://|git@|file://)\S+$")


def _git_source(url: str, work: Path) -> tuple[Path, str]:
    """Rule files from a git repo URL or a GitHub/GitLab folder link (.../tree/<branch>/<folder>), read with your own
    git login. -> (folder, 'url@commit'). Nothing is checked out: some repos have file names Windows can't store,
    so files are read from git and written under safe names."""
    m = re.match(r"^(https://[^/]+/[^/]+/[^/]+?)(?:\.git)?/(?:-/)?tree/([^/]+)(?:/(.+?))?/?$", url)
    repo, ref, sub = (m.group(1), m.group(2), m.group(3) or "") if m else (url, None, "")
    print(f"reading {repo}{f' ({ref})' if ref else ''} ...", flush=True)
    git = work / "git"
    run(["git", "clone", "--quiet", "--depth", "1", "--no-checkout", *(["--branch", ref] if ref else []), repo, git])
    sha = subprocess.check_output(["git", "-C", str(git), "rev-parse", "HEAD"], text=True).strip()
    listing = subprocess.check_output(["git", "-C", str(git), "ls-tree", "-r", "-z", "--name-only", "HEAD", "--",
                                       sub or "."])           # -z: names exactly as stored (no quoting of ü or ")
    names = [n for n in listing.decode("utf-8", "surrogateescape").split("\0")
             if n.lower().endswith((".yaral", ".yaral.txt", ".yl2", ".txt"))]
    if not names:
        die(f"no .yaral files in {repo}{f' under {sub}' if sub else ''} at {sha[:12]}")
    folder = work / "files"
    p = subprocess.run(["git", "-C", str(git), "cat-file", "--batch"],
                       input="".join(f"HEAD:{n}\n" for n in names).encode("utf-8", "surrogateescape"),
                       capture_output=True, check=True)
    data, pos = p.stdout, 0
    for n in names:
        head_end = data.index(b"\n", pos)
        size = int(data[pos:head_end].split()[2])
        out = folder / re.sub(r'[<>:"|?*\x00-\x1f]', "_", n)              # names Windows can store
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data[head_end + 1:head_end + 1 + size])
        pos = head_end + 1 + size + 1
    return folder, f"{repo}@{sha[:12]}"           # paths under folder are the repo paths


def _split_rules(text: str) -> list[tuple[str, str]]:
    """[(rule name, rule text)] - one file may hold several rules (exports often do)."""
    blank = lambda m: re.sub(r"[^\n]", " ", m.group())          # same length, so positions still line up
    masked = re.sub(r"//[^\n]*", blank, re.sub(r"/\*.*?\*/", blank, text, flags=re.S))
    starts = list(re.finditer(r"^[ \t]*rule\s+([A-Za-z0-9_]+)\s*\{", masked, re.M))
    return [(m.group(1), text[m.start():(starts[i + 1].start() if i + 1 < len(starts) else len(text))].strip() + "\n")
            for i, m in enumerate(starts)]


def cmd_import(args):
    """yadda import <environment> <folder | files | git URL>  - load rules from files or a repo (no SecOps login)."""
    import tempfile
    from delib.upstream import _swap_in
    if len(args) < 2:
        die("usage: yadda import <environment> <folder with .yaral files | files... | git repo URL or .../tree/<branch>/<folder>>")
    name = valid_name(args[0])
    c = ENVIRONMENTS / name
    tmp = Path(tempfile.mkdtemp(prefix="yadda-import-"))
    try:
        srcs, origin = [], {}
        for a in args[1:]:
            if GIT_URL.match(a):
                folder, ref = _git_source(a, tmp / f"repo{len(srcs)}")
                srcs.append(folder)
                origin[folder] = ref
            else:
                srcs.append(Path(a))
        files = []
        for s in srcs:
            if s.is_dir():
                files += sorted(p for p in s.rglob("*") if p.is_file() and ".git" not in p.parts
                                and p.name.lower().endswith((".yaral", ".yaral.txt", ".txt", ".yl2")))
            elif s.is_file():
                files.append(s)
            else:
                die(f"not found: {s}")
        rules_dir = (c / "rules").resolve()
        if any(rules_dir == p.resolve() or rules_dir in p.resolve().parents for p in srcs):
            die(f"{c / 'rules'} is where yadda import writes - copy the files somewhere else first")
        # Read and name everything before the old rules are touched.
        found, skipped = [], []
        for p in files:
            rules = _split_rules(read_text(p))
            found += [(p, n, t) for n, t in rules]
            if not rules:
                skipped.append(p.name)
        if not found:
            die(f"no YARA-L rules ('rule <name> {{') in {', '.join(map(str, args[1:]))} - nothing was changed")
        if not c.exists():
            clash = [n for n in environment_names() if n.casefold() == name.casefold()]
            if clash:
                die(f"environment '{clash[0]}' already exists (Windows treats '{name}' as the same folder)")
            shutil.copytree(ENVIRONMENTS / "_template", c)
            print(f"created {c}")
        old_cfg = (yaml_rt().load(read_text(c / "rule_config.yaml")) or {}) if (c / "rule_config.yaml").exists() else {}
        staged = c / "rules.new"
        if staged.exists():
            _rmtree(staged)
        staged.mkdir()
        cfg, taken = {}, set()
        for p, base, text in found:
            rule, n = base, 2
            while rule.casefold() in taken:                  # Windows file names ignore case: Rule_A == rule_a
                rule, n = f"{base}__dup{n}", n + 1
            taken.add(rule.casefold())
            write_text(staged / f"{rule}.yaral", text)
            src = next((f"{origin[s]}:{p.relative_to(s).as_posix()}" for s in origin if s in p.parents), p.name)
            prev = old_cfg.get(rule) or {}                   # re-import keeps rules you disabled / archived
            cfg[rule] = {"enabled": prev.get("enabled", True), "archived": prev.get("archived", False),
                         "imported": str(dt.date.today()), "source_file": src}
        _swap_in(staged, c / "rules")                        # old rules replaced only once the new set is complete
        write_yaml(c / "rule_config.yaml", cfg)
    finally:
        _rmtree(tmp)
    print(f"{c.name}: imported {len(cfg)} rules from {len(files)} files (all treated as enabled)"
          + (f" - source {', '.join(origin.values())}" if origin else ""))
    if skipped:
        print(f"  skipped {len(skipped)} files with no 'rule <name> {{': {', '.join(skipped[:10])}")
    cmd_sync([name])


# ---------------------------------------------------------------- help
HELP_GROUPS = [
    ("Every assessment", ["run"]),
    ("Questions and records", ["check", "score", "test", "actors"]),
    ("Environments and set-up", ["new", "import", "status", "setup"]),
]


HELP_DETAIL = {
    "run": ("yadda run <environment> [-pull -queries -data -evidence -robustness -review -atomics -sigma] [--ask]",
            "Run every step: pull rules, SecOps queries (or the exports in environments/<environment>/inputs/), "
            "evidence scores, robustness, rule review, Atomic Red Team tests, Sigma candidates. Skip a step with -<step>. "
            "Writes the dashboard, workbook and Navigator layers to output/<environment>/<date>/ (copy in latest/). "
            "--ask: assign unknown log types to an ATT&CK platform.",
            ["yadda run acme", "yadda run acme -sigma -robustness", "yadda run newco -pull", "yadda run acme --ask"]),
    "check": ("yadda check <environment> <T-ids | group | software | threat file | --threats> [--layer]",
              "Can we detect X? State per technique, with rules, evidence and the MITRE route. --threats checks everything in THREATS=.",
              ["yadda check acme T1003.001", "yadda check acme APT29 --layer", 'yadda check acme "Cobalt Strike"', "yadda check acme --threats"]),
    "score": ("yadda score <environment> <technique> <-1..5> \"<evidence>\"",
              "Record a detection score by hand, e.g. 4 after a lab test (see shared/score_definitions.md).",
              ['yadda score acme T1053.005 4 "5/14 atomics fired"']),
    "test": ("yadda test <environment> <guid|T1053.005#2> fired|missed|n/a|clear [rule] [\"notes\"]",
             "Record one Atomic Red Team result (the tests to run are in the workbook's Validation sheet).",
             ["yadda test acme 0a8d2c4f fired win_schtasks_create", "yadda test acme T1053.005#4 missed"]),
    "actors": ("yadda actors [--sector S] [--country C] [--region R] [--broad] [--environment X] [--set | --add] | --list",
               "ATT&CK groups by who they target (MISP + ATT&CK). --set replaces THREATS= in environment.env, --add adds to it "
               "(the file is backed up first). --list shows every sector, region and country.",
               ['yadda actors --sector Financial --country "Germany" --environment acme --set']),
    "new": ("yadda new <environment>", "Create environments/<environment> from the template; then fill in environment.env.", ["yadda new acme"]),
    "import": ("yadda import <environment> <folder | files | git URL>",
               "Load YARA-L rules without a SecOps login, from a folder, files or a git repo (a .../tree/<branch>/<folder> "
               "link imports one folder). Rules you disabled stay disabled.",
               ["yadda import acme exports/acme-rules", "yadda import acme https://github.com/acme/detections/tree/main/secops"]),
    "status": ("yadda status", "One line per environment.", []),
    "setup": ("yadda setup [--latest | --check]",
              "Install the tools and data at the versions in tools.lock and requirements.lock. --latest tries the newest "
              "versions and keeps them only if every check passes. --check tests the installed tools.", ["yadda setup", "yadda setup --latest", "yadda setup --check"]),
}


def cmd_help(args=None):
    """yadda help [command]  - this help, or details for one command"""
    args = args or []
    if args and args[0] in HELP_DETAIL:
        usage, what, examples = HELP_DETAIL[args[0]]
        print(f"\n  {usage}\n\n  {what}")
        for e in examples:
            print(f"    e.g. {e}")
        print()
        return
    print("yadda (Yet Another Detection Dashboard, Apparently) - detection coverage for Google SecOps. Run \"yadda help <command>\" for examples.")
    for group, cmds in HELP_GROUPS:
        print(f"  {group}")
        for cmd in cmds:
            usage, what, _ = HELP_DETAIL[cmd]
            print(f"    {usage}")
            print(f"        {what}")
        print()
    print("  yadda go [environment]   jump to the repo or an environment folder (cmd.exe; ./yadda go prints the path)")
    print("  yadda help <command>  or  yadda <command> --help   for examples")


COMMANDS = {"run": cmd_run, "check": cmd_check, "score": cmd_score, "test": cmd_test, "actors": cmd_actors,
            "new": cmd_new, "import": cmd_import, "status": cmd_status, "setup": cmd_setup, "help": cmd_help,
            # single steps of `yadda run`, for re-running one piece (not listed in help)
            "pull": cmd_pull, "sync": cmd_sync, "data": cmd_data, "evidence": cmd_evidence, "review": cmd_review,
            "robustness": cmd_robustness, "sigma": cmd_sigma, "atomics": cmd_atomics, "dashboard": cmd_dashboard,
            "doctor": cmd_doctor, "mapping": cmd_mapping, "metrics": cmd_metrics, "rules": cmd_rules,
            "priorities": cmd_priorities}
