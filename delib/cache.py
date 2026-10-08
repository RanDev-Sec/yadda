"""cache - compute each analysis once per run, however many outputs ask for it.

A result is reused only while the files it was computed from are unchanged (same paths, sizes and modification
times), so a step that rewrites techniques.yaml or drops a new export automatically gets fresh results.
"""
from __future__ import annotations

import functools
from pathlib import Path

from delib.config import SHARED

_store: dict = {}
ENVIRONMENT_FILES = ("environment.env", "rule_config.yaml", "techniques.yaml", "validation.csv", "rule_review.csv",
                     "robustness_rules.csv", "robustness_techniques.csv")


def _stat(p: Path) -> tuple:
    try:
        st = p.stat()
        return (str(p), st.st_mtime_ns, st.st_size)
    except OSError:
        return (str(p), None)


def signature(c: Path) -> tuple:
    """Everything an environment's analysis reads: its files, its exports, its rules, and the shared tables."""
    c = Path(c)
    files = [c / n for n in ENVIRONMENT_FILES]
    files += sorted(p for p in (c / "inputs").iterdir() if p.is_file()) if (c / "inputs").is_dir() else []
    files += sorted(SHARED.glob("*.csv"))
    rules = c / "rules"
    rule_sig = (0, 0)
    if rules.is_dir():
        stats = [p.stat() for p in rules.glob("*.yaral")]
        rule_sig = (len(stats), sum(s.st_mtime_ns for s in stats))
    return tuple(_stat(f) for f in files) + (rule_sig,)


def per_environment(key=lambda *a, **k: ()):
    """Decorator for functions whose first argument is the environment folder. key(*rest) adds whatever else
    distinguishes two calls (e.g. the platforms in scope)."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(c, *args, **kwargs):
            k = (fn.__module__, fn.__name__, str(c), key(*args, **kwargs), signature(c))
            if k not in _store:
                _store[k] = fn(c, *args, **kwargs)
            return _store[k]
        return wrapper
    return deco


def clear() -> None:
    _store.clear()


def per_inventory(fn):
    """Decorator for functions of an inventory file: reused while the file, the other exports next to it and the
    shared tables are unchanged."""
    @functools.wraps(fn)
    def wrapper(f, *args, **kwargs):
        if f is None:
            return fn(f, *args, **kwargs)
        f = Path(f)
        k = (fn.__module__, fn.__name__, _stat(f), tuple(_stat(p) for p in sorted(f.parent.iterdir()) if p.is_file()),
             tuple(_stat(p) for p in sorted(SHARED.glob("*.csv"))), str(f), args, tuple(sorted(kwargs.items())))
        if k not in _store:
            _store[k] = fn(f, *args, **kwargs)
        return _store[k]
    return wrapper
