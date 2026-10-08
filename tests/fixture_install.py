"""Install a fixture environment into environments/<name>, rendering *.tmpl date tokens relative to today."""
from __future__ import annotations

import datetime as dt
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def render(text: str, today: dt.date) -> str:
    def ts(m):
        d = today + dt.timedelta(days=int(m.group(1)))
        return str(int(dt.datetime(d.year, d.month, d.day, 12, tzinfo=dt.timezone.utc).timestamp()))
    text = re.sub(r"\{\{ts:([+-]?\d+)\}\}", ts, text)
    return re.sub(r"\{\{date:([+-]?\d+)\}\}", lambda m: str(today + dt.timedelta(days=int(m.group(1)))), text)


def install(fixture: str, name: str, environments: Path | None = None, today: dt.date | None = None) -> Path:
    environments = environments or ROOT / "environments"
    dst = environments / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(FIXTURES / fixture, dst)
    for t in dst.rglob("*.tmpl"):
        t.with_suffix("").write_text(render(t.read_text(encoding="utf-8"), today or dt.date.today()), encoding="utf-8")
        t.unlink()
    return dst


if __name__ == "__main__":
    print(install(sys.argv[1], sys.argv[2]))
