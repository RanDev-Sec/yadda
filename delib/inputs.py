"""inputs - the SecOps exports an environment's assessment reads, kept in environments/<name>/inputs/.

Drop any export there under any file name: each file is recognised by its columns, and the newest file of each
kind is the one used. `yadda run` fetches them itself when the environment has API access.
"""
from __future__ import annotations

from pathlib import Path

from delib.config import read_csv, write_bytes

KINDS = {
    "inventory": "telemetry inventory (shared/queries/telemetry_inventory.yaral)",
    "rule_health": "rule health (shared/queries/rule_health.yaral)",
    "rule_fp": "rule false positives (shared/queries/rule_fp_rate.yaral)",
    "rule_logtypes": "log types per rule (shared/queries/rule_logtypes.yaral)",
    "product_alerts": "security-product detections with ATT&CK ids (shared/queries/product_alerts.yaral)",
    "host_os": "host operating systems per log type (shared/queries/log_type_host_os.yaral)",
}
_kind_cache: dict = {}


def kind_of(path: Path) -> str | None:
    """Which SecOps export a CSV is, from its columns; None if it isn't one yadda knows."""
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _kind_cache:
        try:
            head = {h.strip().lstrip("$").lower() for h in read_csv(path)[0] if h}
        except SystemExit:
            head = set()
        k = None
        if {"log_type", "technique"} <= head:
            k = "product_alerts"
        elif {"log_type", "os"} <= head and "event_type" not in head:
            k = "host_os"
        elif {"log_type", "event_type"} <= head and head & {"event_count", "events", "count"}:
            k = "inventory"
        elif "log_type" in head and head & {"rule_name", "display_name"}:
            k = "rule_logtypes"
        elif head & {"reason", "malicious", "not_malicious"}:
            k = "rule_fp"
        elif head & {"detection_time", "last_fired", "latest_detection_time", "detection_count", "detections",
                     "total_detection_count"}:
            k = "rule_health"
        _kind_cache[key] = k
    return _kind_cache[key]


def folder(c: Path) -> Path:
    return c / "inputs"


def _migrate(c: Path) -> None:
    """Move exports saved next to environment.env as <kind>.csv into inputs/."""
    for kind in KINDS:
        old = c / f"{kind}.csv"
        if old.is_file():
            d = folder(c)
            d.mkdir(exist_ok=True)
            new = d / old.name
            if not new.exists():
                old.replace(new)


def files(c: Path) -> dict[str, list[Path]]:
    """{kind: [files, newest first]} plus 'unknown' for CSVs that aren't a known export."""
    _migrate(c)
    out = {k: [] for k in KINDS} | {"unknown": []}
    d = folder(c)
    if d.is_dir():
        for f in sorted(d.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file() and f.suffix.lower() in (".csv", ".tsv", ".txt") and not f.name.lower().startswith("readme"):
                out[kind_of(f) or "unknown"].append(f)
    return out


def current(c: Path, kind: str) -> Path | None:
    """The export of this kind in use: the newest one in inputs/."""
    found = files(c)[kind]
    return found[0] if found else None


def add(c: Path, src: Path) -> Path:
    """Copy an export given on the command line into inputs/ (it becomes the newest of its kind)."""
    src = Path(src)
    d = folder(c)
    d.mkdir(exist_ok=True)
    if src.resolve().parent == d.resolve():
        src.touch()                                   # already there: make it the newest of its kind
        return src
    dst = d / src.name
    n = 2
    while dst.exists() and dst.read_bytes() != src.read_bytes():
        dst = d / f"{src.stem}_{n}{src.suffix}"
        n += 1
    write_bytes(dst, src.read_bytes())
    return dst


def product_alerts(c: Path) -> dict:
    """{technique: {log type: events}} from the newest security-product detections export; {} when there is none.
    The sub-technique is used when the product gave one. Ids ATT&CK has replaced are mapped to the current ones."""
    import re
    from delib.attack import attack
    f = current(c, "product_alerts")
    if not f:
        return {}
    head, rows = read_csv(f)
    replaced = attack()["replaced"]
    out: dict = {}
    for r in rows:
        r = {k.strip().lstrip("$").lower(): (v or "").strip() for k, v in r.items() if k}
        t = r.get("subtechnique") if re.fullmatch(r"T\d{4}\.\d{3}", r.get("subtechnique", "").upper()) else r.get("technique", "")
        t = t.upper()
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
            continue
        t = replaced.get(t, t)
        n = int(float(r.get("event_count") or 0) or 0)
        lt = r.get("log_type") or "?"
        out.setdefault(t, {})
        out[t][lt] = out[t].get(lt, 0) + n
    return out
