#!/usr/bin/env python3
"""yadda (Yet Another Detection Dashboard, Apparently) - detection coverage for Google SecOps. Run "yadda help".

Wraps existing tools and data; does not replace them:
  Google SecOps Content Manager  pull deployed rules from an environment's SecOps instance
  MITRE ATT&CK data              detection strategies and analytics (the routes yadda measures against)
  MITRE Detection Coverage Calc  robustness and implementation coverage (yadda robustness)
  SigmaHQ + pySigma              community rules converted to YARA-L for the gaps
  Atomic Red Team, MISP, CTID    tests, threat-actor targeting, Attack Flow, Technique Inference Engine

Scores are kept in techniques.yaml in DeTT&CT's technique-administration format, so the file opens in DeTT&CT.
The code lives in delib/; this file is only the entry point used by yadda.cmd (Windows) and ./yadda (macOS, Linux).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from delib import (actors, analysis, attack, commands, config, dashboard, doctor, facts, priorities,  # noqa: E402
                   robustness, secops_api, telemetry, upstream, validation, yaral)
from delib.commands import COMMANDS, cmd_help  # noqa: E402

# Re-export the delib functions, so scripts can use `import yadda; yadda.load_techniques(...)`.
for _m in (config, attack, yaral, upstream, telemetry, facts, validation, robustness, actors, secops_api,
           priorities, analysis, dashboard, doctor, commands):
    globals().update({k: v for k, v in vars(_m).items() if not k.startswith("__")})


def main() -> None:
    # Windows defaults to cp1252 for files, and Content Manager opens files without an encoding:
    # restart in Python's UTF-8 mode so it and every child process read and write UTF-8.
    if os.name == "nt" and not sys.flags.utf8_mode:
        os.environ["PYTHONUTF8"] = "1"
        sys.exit(subprocess.call([sys.executable, "-X", "utf8", __file__, *sys.argv[1:]]))
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        if len(sys.argv) >= 2:
            print(f"yadda: unknown command '{sys.argv[1]}'")
        cmd_help()
        sys.exit(0 if len(sys.argv) < 2 else 1)
    if any(a in ("-h", "--help") for a in sys.argv[2:]):
        cmd_help([sys.argv[1]])
        sys.exit(0)
    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except BrokenPipeError:                       # output piped into `more` / `head` that closed early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit("yadda: stopped (files are written atomically, so none is half-written)")


if __name__ == "__main__":
    main()
