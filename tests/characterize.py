"""Black-box run of the whole pipeline on a fixture environment; writes normalised outputs to a folder.

Used by test_golden.py: the outputs are compared with tests/golden/<fixture>/. When a change is *meant* to alter
results, regenerate with  python tests/characterize.py --update  and review the git diff of tests/golden/.
"""
from __future__ import annotations

import datetime as dt
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_install import ROOT, install  # noqa: E402

PY = sys.executable
ENVIRONMENT = "acmetest"
STEPS = [
    ("sync", ["sync", ENVIRONMENT]),
    ("data", ["data", ENVIRONMENT]),                       # the exports are in the environment's inputs/ folder
    ("evidence", ["evidence", ENVIRONMENT]),
    ("review", ["review", ENVIRONMENT]),
    ("robustness", ["robustness", ENVIRONMENT]),
    ("metrics", ["metrics", ENVIRONMENT]),
    ("rules", ["rules", ENVIRONMENT, "50"]),
    ("priorities", ["priorities", ENVIRONMENT, "15"]),
    ("check", ["check", ENVIRONMENT, "T1053.005", "T1003.001", "T1086", "APT29"]),
    ("dashboard", ["dashboard", ENVIRONMENT]),
    ("run", ["run", ENVIRONMENT, "-pull", "-queries", "-sigma", "-layers"]),
]
FILES = ["rule_review.csv", "rule_ranking.csv", "robustness_rules.csv", "robustness_techniques.csv",
         "threat_priorities.csv", "threat_data_needs.csv"]


def normalise(text: str) -> str:
    today = dt.date.today()
    text = text.replace(str(ROOT), "<ROOT>").replace("\\", "/")
    text = re.sub(r"\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?", "<DATE>", text)
    text = re.sub(r"\b[0-9a-f]{7} <DATE>", "<DCC-VERSION>", text)
    text = re.sub(r"(?m)^(  \S+\s+\S+\s+)\d+s  ", r"\1<T>s  ", text)        # step timings in yadda run
    return text.replace(str(today), "<TODAY>")


def techniques_summary(c: Path) -> str:
    sys.path.insert(0, str(ROOT))
    import yadda  # noqa: PLC0415
    t = yadda.load_techniques(c)
    rows = [f"{tid},{v['score']},{'|'.join(sorted(v['rules']))}" for tid, v in sorted(t.items())
            if v["score"] >= 0 or v["rules"]]
    return "technique,score,rules\n" + "\n".join(rows) + "\n"


def model_dump(c: Path) -> dict[str, str]:
    """The telemetry methodology's results: per technique state + best MITRE route, and per platform what is seen."""
    sys.path.insert(0, str(ROOT))
    from delib.facts import scope_states  # noqa: PLC0415
    from delib.routes import inventory_file, observed, platform_summary  # noqa: PLC0415
    from delib.telemetry import _dc_sources, _mapping  # noqa: PLC0415
    rows, in_scope, plats = scope_states(c)
    lines = ["technique,state,route_platform,route_level,inputs_seen,missing_inputs"]
    for r in sorted(rows, key=lambda r: r["id"]):
        b = r["route"]
        miss = " | ".join(i["dc"] for i in b["inputs"] if i["measurable"] and not i["seen"]) if b else ""
        lines.append(f"{r['id']},{r['state']},{b['platform'] if b else ''},{b['level'] if b else ''},"
                     f"{str(b['seen']) + '/' + str(b['needed']) if b else ''},{miss}")
    obs = observed(inventory_file(c))
    plat = ["platform,observed,log_types,routes,all,some,none,unseen,unknown,top_missing"]
    for p in platform_summary(in_scope, plats, obs, set(_dc_sources(_mapping()))):
        plat.append(f"{p['platform']},{p['observed']},{' '.join(sorted(p['log_types']))} +net: "
                    f"{' '.join(sorted(p['network_log_types']))},{p['routes']},{p['all']},"
                    f"{p['some']},{p['none']},{p['unseen']},{p['unknown']},"
                    + " | ".join(f"{m['dc']}{'[' + m['product'] + ']' if m['product'] else ''}:{len(m['completes'])}/{len(m['techniques'])}"
                               for m in p["missing"][:5]))
    from delib.analysis import _analysis, technique_support  # noqa: PLC0415
    from delib.facts import _rule_facts  # noqa: PLC0415
    from delib.procedures import threat_context  # noqa: PLC0415
    an = _analysis(c)
    counts = "\n".join(f"{k},{v}" for k, v in sorted(an["counts"].items()))
    sup = ["technique,rule,tags,state,noisy"] + [f"{t},{s['rule']},{s['tags']},{s['state']},{s['noisy']}"
                                                  for t, ss in sorted(technique_support(_rule_facts(c)).items()) for s in ss]
    tc = threat_context(c)
    ctx = ["# software (ATT&CK): name,type,used_by,techniques in scope,out of scope,detected,first gaps"]
    ctx += [f"{r['name']},{r['type']},{'|'.join(r['used_by'])},{r['techniques']},{r['out_of_scope']},{r['detected']},"
            f"{'|'.join(r['gaps'][:3])}" for r in tc["software"]]
    ctx += ["# campaigns"] + [f"{r['name']},{'|'.join(r['used_by'])},{r['techniques']},{r['detected']}" for r in tc["campaigns"]]
    ctx += [f"# procedures: {len(tc['procedures'])}"] + [f"{p['technique']},{p['state']},{p['by']}" for p in tc["procedures"][:15]]
    ctx += ["# flows: name,relevant_to,steps,actions,judged,covered,first_seen_step"]
    ctx += [f"{f['name']},{'|'.join(f['relevant_to'])},{f['total_steps']},{f['actions']},{f['judged']},{f['covered']},{f['first_seen_step']}"
            for f in tc["flows"]]
    ctx += ["# inferred (TIE): threat,rank,technique,state"] + [f"{r['threat']},{r['rank']},{r['technique']},{r['state']}"
                                                               for r in tc["inferred"]]
    return {"technique_states.csv": "\n".join(lines) + "\n", "telemetry_seen.csv": "\n".join(plat) + "\n",
            "counts.csv": counts + "\n", "technique_support.csv": "\n".join(sup) + "\n",
            "threat_context.csv": "\n".join(ctx) + "\n"}


def run(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    c = install("acme", ENVIRONMENT)
    try:
        for name, args in STEPS:
            p = subprocess.run([PY, "yadda.py", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=600)
            (out / f"{name}.out").write_text(normalise(f"exit={p.returncode}\n{p.stdout}{p.stderr}"), encoding="utf-8")
        run_dir = ROOT / "output" / ENVIRONMENT / str(dt.date.today())
        for f in FILES:
            src = c / f if (c / f).exists() else run_dir / "data" / f
            if src.exists():
                (out / f).write_text(normalise(src.read_text(encoding="utf-8-sig")), encoding="utf-8")
        listing = sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file())
        (out / "run_outputs.txt").write_text("\n".join(listing) + "\n", encoding="utf-8")
        for name in ("telemetry_seen.csv", "next_actions.csv", "funnel.csv"):
            if (run_dir / "data" / name).exists():
                (out / f"run_{name}").write_text(normalise((run_dir / "data" / name).read_text(encoding="utf-8-sig")),
                                                 encoding="utf-8")
        (out / "techniques_summary.csv").write_text(techniques_summary(c), encoding="utf-8")
        for name, text in model_dump(c).items():
            (out / name).write_text(text, encoding="utf-8")
        # The same environment without its Microsoft 365 and Okta telemetry: those routes must lose their inputs.
        sys.path.insert(0, str(ROOT))
        from delib import inputs  # noqa: PLC0415
        inv = inputs.current(c, "inventory")
        inv.write_text("".join(l for l in inv.read_text(encoding="utf-8").splitlines(True)
                               if not l.startswith(("OFFICE_365", "OKTA"))), encoding="utf-8")
        for name, text in model_dump(c).items():
            (out / name.replace(".csv", "_without_m365_okta.csv")).write_text(text, encoding="utf-8")
        shadow = c / "robustness" / "shadow"
        if shadow.exists():
            (out / "shadow").mkdir()
            for f in sorted(shadow.glob("*.yml")):
                shutil.copy(f, out / "shadow" / f.name)
    finally:
        shutil.rmtree(c, ignore_errors=True)
        shutil.rmtree(ROOT / "output" / ENVIRONMENT, ignore_errors=True)


if __name__ == "__main__":
    target = Path(__file__).resolve().parent / ("golden/acme" if "--update" in sys.argv else "_last_run/acme")
    run(target)
    print(f"wrote {target}")
