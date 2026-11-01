"""--jobs N on the batched runner: parse contract + end-to-end parallel smoke.

Why this file exists: the runner is the gate's floor.  A flag that silently
fell back to serial on a typo ("--jobs 04x") would LOOK like parallelism
and deliver a 4x-slower gate -- the same "looks green, means nothing" trap
the runner already fights one level up with skip reporting.  So:

  * the parse contract fails loudly on every malformed shape;
  * a real two-file run through BOTH modes proves the parallel path
    returns the same exit code and the same per-file verdicts as the
    serial one on this machine, today (not "should work in theory").

The e2e leg spawns real pytest subprocesses on purpose: the parallel unit
IS a subprocess, and a fake would only prove the fake (Phase 201 续二's
"替身保真度" lesson).  Fast, green, loopback-free files are chosen so the
guard itself stays seconds-cheap.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _runner():
    spec = importlib.util.spec_from_file_location(
        "_batched", os.path.join(ROOT, "tests", "run_all_batched.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RUNNER = _runner()


# --------------------------------------------------------------- parse contract

def test_jobs_defaults_to_one():
    """No flag == the historical sequential runner.  Byte-identical default."""
    assert RUNNER._parse_jobs(["run_all_batched.py"]) == 1
    assert RUNNER._parse_jobs(["run_all_batched.py", "--quiet"]) == 1


@pytest.mark.parametrize("argv,expected", [
    (["--jobs", "4"], 4),
    (["--jobs", "1"], 1),
    (["--quiet", "--jobs", "2", "test_x.py"], 2),
    (["--jobs", "16"], 16),
])
def test_jobs_parses_valid_values(argv, expected):
    assert RUNNER._parse_jobs(argv) == expected


@pytest.mark.parametrize("bad", [
    ["--jobs"],            # no value at all
    ["--jobs", "x"],       # not a number
    ["--jobs", "2.5"],     # not an integer
    ["--jobs", "0"],       # zero workers would deadlock the pool
    ["--jobs", "-2"],      # negative
])
def test_jobs_malformed_fails_loudly(bad):
    """Silent fallback to 1 would be the exact defect this guard exists for."""
    with pytest.raises(SystemExit):
        RUNNER._parse_jobs(bad)


# ----------------------------------------------------- end-to-end parallel smoke

# Fast, green, loopback-free: both ran green in the 2026-11-01 50-test
# static-gates batch, and neither opens a socket.
_FILES = ["test_doc_code_counts.py", "test_quick_gate_slice.py"]


def test_parallel_run_matches_serial(monkeypatch, capsys):
    """Same files, same gate entry point, jobs=1 vs jobs=2.

    The claim under test: --jobs changes WHERE the wall clock goes, not
    what the gate says.  Exit code, the green-count line, and every
    per-file verdict must be identical across the two modes on this
    host, today.  Wall-clock seconds are deliberately NOT compared --
    they are the thing that is supposed to move.
    """
    verdicts = {}
    for jobs in ("1", "2"):
        argv = ["run_all_batched.py", "--jobs", jobs] + _FILES
        monkeypatch.setattr(sys, "argv", argv)
        rc = RUNNER.main()
        out = capsys.readouterr().out
        assert rc == 0, f"jobs={jobs} exited {rc}; gate must be green"
        assert "2/2 files green" in out, (
            f"jobs={jobs} summary missing green count: {out!r}")
        # Per-file verdict lines: "ok  <file>" / "skip <file>" / "FAIL ...".
        # In parallel mode these arrive in COMPLETION order, so compare
        # as a file->label map, not as an ordered list.
        file_labels = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("ok", "skip", "FAIL"):
                file_labels[parts[1]] = parts[0]
        assert set(file_labels) == set(_FILES), (
            f"jobs={jobs} did not report a verdict for every file: "
            f"{sorted(file_labels)}")
        verdicts[jobs] = file_labels
    assert verdicts["1"] == verdicts["2"], (
        f"serial vs parallel verdicts diverged: "
        f"serial={verdicts['1']} parallel={verdicts['2']}")


def test_run_one_returns_the_documented_record_shape(monkeypatch):
    """The pool aggregates on this tuple; its shape is load-bearing.

    (file, verdict, skipped, whole_file, seconds) -- verdict from the
    three-way contract, skip counts from the summary parser.  Verified
    against one real subprocess run, not a mock (the unit IS a
    subprocess; mocking it would prove nothing about the runner).
    """
    monkeypatch.setattr(sys, "argv", ["run_all_batched.py"])
    record = RUNNER._run_one("test_doc_code_counts.py", quiet=True)
    assert len(record) == 5
    f, verdict, skipped, whole, secs = record
    assert f == "test_doc_code_counts.py"
    assert verdict in ("green", "whole-skip", "red")
    assert isinstance(skipped, int) and skipped >= 0
    assert isinstance(whole, bool)
    assert secs > 0
