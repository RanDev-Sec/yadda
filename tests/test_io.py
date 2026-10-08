"""File reading/writing helpers: encodings, delimiters, atomic writes (no third-party tools needed)."""
import csv

import pytest

from delib import config
from delib.config import read_csv, read_env, read_text, write_csv, write_text


def test_read_text_handles_bom_cp1252_and_utf16(tmp_path):
    (tmp_path / "a").write_bytes("﻿café".encode("utf-8"))
    (tmp_path / "b").write_bytes("café".encode("cp1252"))
    (tmp_path / "c").write_text("café", encoding="utf-16")
    assert [read_text(tmp_path / x) for x in "abc"] == ["café"] * 3


def test_read_csv_sniffs_semicolons_and_cp1252(tmp_path):
    f = tmp_path / "x.csv"
    f.write_bytes("rule;decision\nrègle_1;keep\n".encode("cp1252"))
    head, rows = read_csv(f)
    assert head == ["rule", "decision"] and rows == [{"rule": "règle_1", "decision": "keep"}]


def test_read_csv_comma_with_quoted_thousands(tmp_path):
    f = tmp_path / "x.csv"
    f.write_text('﻿log_type,event_count\nWINEVTLOG,"1,234"\n', encoding="utf-8")
    assert read_csv(f)[1] == [{"log_type": "WINEVTLOG", "event_count": "1,234"}]


def test_write_is_atomic_when_interrupted(tmp_path, monkeypatch):
    f = tmp_path / "keep.csv"
    f.write_text("original\n", encoding="utf-8")

    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(config.os, "replace", boom)
    with pytest.raises(KeyboardInterrupt):
        write_text(f, "new content that never lands\n")
    assert f.read_text(encoding="utf-8") == "original\n"
    assert [p.name for p in tmp_path.iterdir()] == ["keep.csv"]       # temp file cleaned up


def test_write_csv_round_trip_and_extra_columns(tmp_path):
    f = tmp_path / "v.csv"
    write_csv(f, ["a", "b"], [{"a": "1", "b": "2", "c": "kept"}])
    with f.open(encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    assert rows == [{"a": "1", "b": "2", "c": "kept"}]                # unknown columns are not dropped


def test_locked_file_gives_a_plain_message(tmp_path, monkeypatch):
    def locked(*a, **k):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(config.os, "replace", locked)
    with pytest.raises(SystemExit) as e:
        write_text(tmp_path / "open_in_excel.csv", "x")
    assert "open in another program" in str(e.value.code)


def test_read_env_strips_quotes(tmp_path):
    f = tmp_path / "environment.env"
    f.write_text('THREATS="G0016, APT29"\nPLATFORMS=\'Windows\'\n# X=1\n', encoding="utf-8")
    assert read_env(f) == {"THREATS": "G0016, APT29", "PLATFORMS": "Windows"}
