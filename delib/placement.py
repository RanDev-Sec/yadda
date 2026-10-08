"""placement - put log types yadda doesn't know on an ATT&CK platform, by asking you (yadda run <environment> --ask).

Answers go into shared/log_type_platforms.csv, so a log type is placed once for every environment. Nothing is placed
by guessing: a vendor name (ORACLE_*) can be a database, a cloud or an identity provider, so only you decide.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

from delib.config import SHARED

CHOICES = [  # (label, platforms column value)
    ("Windows", "Windows"), ("Linux", "Linux"), ("macOS", "macOS"), ("Identity Provider", "Identity Provider"),
    ("Office Suite", "Office Suite"), ("SaaS", "SaaS"), ("IaaS", "IaaS"), ("Containers", "Containers"),
    ("ESXi", "ESXi"), ("Network Devices (the device's own logs)", "Network Devices"),
    ("Network sensor / firewall traffic (network inputs on every platform)", "network"),
    ("Security-product alert feed (not telemetry)", "alerts"),
    ("No ATT&CK platform (database, PAM, collector ...)", ""),
]


def _csv_field(v: str) -> str:
    return f'"{v}"' if any(ch in v for ch in ',"\n') else v


def add_row(log_type: str, platforms: list[str], note: str, table: Path | None = None) -> None:
    """Append an exact-match row for one log type to the platform table (keeps its line endings)."""
    table = table or SHARED / "log_type_platforms.csv"
    text = table.read_text(encoding="utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    row = ",".join([re.escape(log_type), ";".join(p for p in platforms if p), _csv_field(note.replace('"', "'"))])
    table.write_text(text.rstrip("\r\n") + nl + row + nl, encoding="utf-8", newline="")


def ask(environment: str, unplaced: list[tuple[str, int, str]], read=input, write=print, table: Path | None = None) -> int:
    """unplaced: [(log type, events, evidence text)]. Returns how many were placed. Enter skips one, q stops."""
    if not unplaced:
        write("nothing to place")
        return 0
    if read is input and not sys.stdin.isatty():
        write("--ask needs an interactive terminal; skipped")
        return 0
    write(f"\n{len(unplaced)} log types aren't on the platform table. For each, pick the platform(s) it belongs to.")
    write("  " + "  ".join(f"{i}) {label}" for i, (label, _) in enumerate(CHOICES, 1)))
    placed = 0
    for lt, events, evidence in unplaced:
        write(f"\n{lt}: {events:,} events. {evidence}")
        while True:
            ans = read("  platform number(s), comma-separated (Enter = skip, q = stop): ").strip().lower()
            if ans in ("", "q"):
                break
            nums = [int(x) for x in re.split(r"[ ,]+", ans) if x.isdigit()]
            if not nums or any(n < 1 or n > len(CHOICES) for n in nums):
                write(f"  numbers 1-{len(CHOICES)} please")
                continue
            values = [CHOICES[n - 1][1] for n in nums]
            if len(nums) > 1 and any(v in ("", "alerts") for v in values):
                write("  'alert feed' and 'no platform' can't be combined with a platform")
                continue
            what = read("  what is it (one line, e.g. 'database audit log'): ").strip() or lt
            add_row(lt, values, f"{what} (placed {dt.date.today()})", table)   # no environment name: the table is shared
            placed += 1
            write(f"  {lt} -> {', '.join(CHOICES[n - 1][0] for n in nums)}")
            break
        if ans == "q":
            break
    write(f"\n{placed} placed in {table or SHARED / 'log_type_platforms.csv'} (used for every environment)")
    return placed
