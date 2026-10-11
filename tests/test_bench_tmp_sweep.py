# -*- coding: utf-8 -*-
"""Phase 221: killed benchmark runs must not accumulate report temp files.

Every case writes its raw CLI report into a per-thread temp file under
``benchmark/results/`` (mkstemp -> ``tmp*.json``).  ``atexit`` removes them,
but a run that is KILLED never reaches ``atexit`` -- and this repo has
cancelled more benchmark runs on Windows than it has completed ones.  252
orphans had piled up (1.5 MB); nothing referenced them, and every later
``ls results/`` had to sort past them.

``_sweep_stale_report_tmps`` cleans them at the moment the runner creates its
OWN temp file.  The guard that makes it safe is the age threshold: a
CONCURRENTLY running benchmark owns live temp files of exactly the same
shape, and age is the only signal that tells the two apart.  These tests pin
both halves -- the sweep, and the refusal to eat a live file.
"""
from __future__ import annotations

import os
import sys
import time

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from benchmark import runner as R  # noqa: E402


def _mk(path, age_hours=0.0):
    """Create a temp-shaped file with a chosen mtime age."""
    path.write_text("{}", encoding="utf-8")
    if age_hours:
        t = time.time() - age_hours * 3600
        os.utime(str(path), (t, t))
    return path


def test_sweep_removes_orphans_older_than_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "_RESULTS_DIR", tmp_path)
    old = _mk(tmp_path / "tmpold1.json", age_hours=8)
    old2 = _mk(tmp_path / "tmpold2.json", age_hours=24)

    assert R._sweep_stale_report_tmps() == 2
    assert not old.exists() and not old2.exists()


def test_sweep_leaves_a_concurrent_runs_live_files_alone(tmp_path, monkeypatch):
    """The load-bearing half: age is the ONLY thing separating an orphan from
    another benchmark's in-flight worker file.  A sweep with no age guard
    would delete a concurrent run's report mid-write and lose that case."""
    monkeypatch.setattr(R, "_RESULTS_DIR", tmp_path)
    live = _mk(tmp_path / "tmplive1.json", age_hours=0)

    assert R._sweep_stale_report_tmps() == 0
    assert live.exists(), "a fresh temp file belongs to a running benchmark"


def test_sweep_ignores_files_that_are_not_temp_shaped(tmp_path, monkeypatch):
    """results/ also holds every calibrated artifact (p208_full_sync.json and
    friends).  The matcher must be exactly mkstemp's shape, never '*.json'."""
    monkeypatch.setattr(R, "_RESULTS_DIR", tmp_path)
    keep = [
        _mk(tmp_path / "p208_full_sync.json", age_hours=48),
        _mk(tmp_path / "report.json", age_hours=48),
        _mk(tmp_path / "tmpnotjson.txt", age_hours=48),
    ]

    assert R._sweep_stale_report_tmps() == 0
    assert all(p.exists() for p in keep)


def test_sweep_survives_a_vanished_results_dir(tmp_path, monkeypatch):
    """A missing/unreadable directory returns 0 instead of raising -- the
    sweep runs inside the benchmark's own write path and must never be the
    reason a run dies."""
    monkeypatch.setattr(R, "_RESULTS_DIR", tmp_path / "gone")
    assert R._sweep_stale_report_tmps() == 0


def test_sweep_tolerates_a_file_deleted_between_listdir_and_unlink(
        tmp_path, monkeypatch):
    """TOCTOU: a concurrent runner may finish and unlink its own temp file
    right after listdir() returned the name.  The OSError guard makes that
    a no-op rather than a crash."""
    monkeypatch.setattr(R, "_RESULTS_DIR", tmp_path)
    victim = _mk(tmp_path / "tmpracy.json", age_hours=8)

    real_unlink = os.unlink
    state = {"calls": 0}

    def flaky_unlink(p):
        state["calls"] += 1
        if state["calls"] == 1:
            real_unlink(p)          # someone else got there first
            raise FileNotFoundError(p)
        return real_unlink(p)

    monkeypatch.setattr(os, "unlink", flaky_unlink)
    assert R._sweep_stale_report_tmps() == 0
    assert not victim.exists()