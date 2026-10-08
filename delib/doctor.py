"""doctor - checks every place yadda depends on another tool's internals (flags, classes, private attributes, file
columns, data model). Run by `yadda doctor`, by `yadda setup --latest` before a new version is pinned, and by the
test suite (tests/test_upstream_contract.py)."""
from __future__ import annotations

import csv
import json
import subprocess
import sys

from delib.config import CONTENT_MANAGER, DCC_REPO, TOOLS, die


def _py(code: str, cwd=None, timeout=120) -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-c", code], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def checks(only: str | None = None) -> list[tuple[str, bool, str]]:
    """[(what, ok, detail)] - one entry per contract yadda relies on (`only`: just the check with that name)."""
    out = []

    def check(name, fn):
        if only and name != only:
            return
        try:
            ok, detail = fn()
        except SystemExit as e:
            ok, detail = False, str(e.code)
        except Exception as e:  # noqa: BLE001 - report anything, never crash the doctor
            ok, detail = False, f"{type(e).__name__}: {e}"
        out.append((name, bool(ok), detail))

    # ---- ATT&CK data model
    def attack_model():
        from delib.attack import attack_version, tech_index
        ti = tech_index()["techs"]            # dies if fewer than half the techniques have data components
        n = sum(1 for t in ti.values() if t["dcs"])
        return True, f"ATT&CK {attack_version()}: {n} of {len(ti)} techniques have data components"
    check("ATT&CK data (detection strategies -> data components)", attack_model)

    # ---- Google Content Manager
    def content_manager():
        if not CONTENT_MANAGER.exists():
            return False, "not installed"
        rc, txt = _py("from content_manager.rules import Rules\n"
                      "assert callable(getattr(Rules, 'parse_rules', None)), 'Rules.parse_rules'\nprint('ok')",
                      cwd=CONTENT_MANAGER)
        return rc == 0, "Rules.parse_rules present (yadda renames duplicate rule names through it)" if rc == 0 else txt.strip()[-300:]
    check("Google SecOps Content Manager", content_manager)

    # ---- MITRE Detection Coverage Calculator
    def dcc():
        from delib.robustness import _dcc_dictionary
        from delib.telemetry import _dcc_mappings
        from delib.upstream import _dcc
        d = _dcc()
        h = subprocess.run([sys.executable, str(d["script"]), "--help"], capture_output=True, text=True, timeout=120).stdout
        if "--out-prefix" not in h:
            return False, "no --out-prefix option"
        rows = _dcc_dictionary(d)
        maps = _dcc_mappings(d)
        return True, f"{d['version']}: {len(rows)} scored fields, {len(maps)} mapped event IDs"
    check("MITRE Detection Coverage Calculator", dcc if DCC_REPO.exists() else lambda: (False, "not installed - yadda robustness --update"))

    # ---- Sigma -> YARA-L (pySigma + Google SecOps backend) for yadda sigma
    def sigma_conv():
        from delib.sigma import SIGMA_REPO, convert
        if not (SIGMA_REPO / "rules").is_dir():
            return False, "SigmaHQ rules not installed (yadda setup)"
        rule = ("title: yadda doctor\nid: 00000000-0000-0000-0000-000000000001\nstatus: test\n"
                "logsource: {category: process_creation, product: windows}\n"
                "detection:\n  sel:\n    Image|endswith: '\\\\cmd.exe'\n  filter:\n    ParentImage|endswith: "
                "'\\\\explorer.exe'\n    CommandLine|contains: 'x'\n  condition: sel and not filter\n"
                "tags: [attack.t1059.003]\nlevel: low\n")
        r, why = convert(rule)
        if r is None:
            return False, f"test rule not converted: {why}"
        body = r["yaral"].split("events:")[1]
        ok = ('"PROCESS_LAUNCH"' in body and " or " in body and body.count("!=") == 2
              and "T1059.003" in r["yaral"] and "\n  condition:" in r["yaral"])
        net = ("title: yadda doctor 2\nid: 00000000-0000-0000-0000-000000000002\nstatus: test\n"
               "logsource: {category: network_connection, product: windows}\n"
               "detection:\n  sel:\n    Image|endswith: ['\\\\a.exe', '\\\\b.exe']\n  f:\n    DestinationPort: [80, 443]\n"
               "  condition: sel and not f\ntags: [attack.t1071]\nlevel: low\n")
        r2, why2 = convert(net)
        b2 = r2["yaral"] if r2 else why2
        ok = ok and r2 is not None and "port != 80 and" in b2 and "port != 443" in b2 and b2.count("$/ nocase") == 2
        n = sum(1 for _ in (SIGMA_REPO / "rules").rglob("*.yml"))
        return ok, (f"converter works ({n} SigmaHQ rules)" if ok else "converter output changed shape:\n" + body[:300])
    check("Sigma to YARA-L converter", sigma_conv)

    # ---- Atomic Red Team index + MISP galaxies (file formats)
    def art():
        files = sorted((TOOLS / "art").glob("*-index.csv"))
        if not files:
            return False, "no index downloaded yet (yadda atomics downloads it)"
        head = next(csv.reader(files[0].open(encoding="utf-8")))
        need = ["Technique #", "Test #", "Test Name", "Test GUID", "Executor Name"]
        missing = [h for h in need if h not in head]
        return not missing, "columns present" if not missing else f"missing columns {missing}"
    check("Atomic Red Team index columns", art)

    def misp():
        f = TOOLS / "misp" / "threat-actor.json"
        if not f.exists():
            return False, "not downloaded yet (yadda actors downloads it)"
        vals = json.load(f.open(encoding="utf-8")).get("values") or []
        ok = vals and all(isinstance(v.get("meta", {}), dict) for v in vals[:50]) and "value" in vals[0]
        return bool(ok), f"{len(vals)} threat actors" if ok else "unexpected structure"
    check("MISP threat-actor galaxy", misp)

    # ---- Attack Flow corpus: actions carry ATT&CK ids, arrows join them through anchors and latches
    def attack_flow():
        from delib.flows import CORPUS, corpus
        if not CORPUS.exists():
            return False, "not installed - yadda setup"
        fs = corpus()
        steps = [s for f in fs for s in f["steps"]]
        chained = sum(1 for f in fs if max(s["step"] for s in f["steps"]) > 1)
        ok = len(fs) >= 10 and chained >= len(fs) * 0.8
        return ok, f"{len(fs)} flows, {len(steps)} ATT&CK steps, {chained} with ordered steps"
    check("Attack Flow corpus", attack_flow)

    # ---- TIE: the trained model's arrays and the prediction yadda ported from TIE's web app
    def tie():
        from delib.inference import MODEL, model, predict
        from delib.attack import tech_index
        if not MODEL.exists():
            return False, "not installed - yadda setup"
        ids, V, c, rc = model()
        known = set(tech_index()["techs"])
        bad = [t for t in ids if t not in known]
        top = predict({"T1566.001", "T1204.002"})
        ok = V.shape == (len(ids), V.shape[1]) and 0 < c < 1 and rc >= 0 and len(bad) < len(ids) * 0.05 and top
        return ok, (f"{len(ids)} techniques ({len(bad)} not in the installed ATT&CK), c={c:g}; "
                    f"phishing attachment -> {top[0][0] if top else '?'}")
    check("Technique Inference Engine model", tie)
    return out


def cmd_doctor(args):
    """yadda doctor  - check that the installed tools still work the way yadda uses them."""
    res = checks()
    width = max(len(n) for n, _, _ in res)
    for name, ok, detail in res:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name:{width}}  {detail}")
    bad = [n for n, ok, _ in res if not ok]
    if bad:
        die(f"{len(bad)} check(s) failed - `yadda setup` reinstalls the pinned versions that are known to work")
    print("all checks passed")
