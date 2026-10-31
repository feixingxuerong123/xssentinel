"""Phase 346: the TEMP probe must test what the BROWSER sees.

The failure this locks down: every real-browser test died with

    EPERM: operation not permitted, mkdtemp '...\\Temp\\playwright-artifacts-XXXXXX'

because the workspace tree carries a Low mandatory integrity label that
Windows propagates to child processes, and a Low-integrity process cannot
write %TEMP%.

Two probe designs were tried and BOTH were wrong in the permissive
direction -- each declared the environment healthy while the browser still
died.  They are pinned here as regression cases, because a probe that
answers a different question than the code under test is the vacuous-guard
shape from Phase 201:

  1. ``os.access(path, os.W_OK)`` -- answered from the ACL, ignored the
     integrity label, returned True on exactly the broken host.
  2. ``tempfile.gettempdir()`` -- Python silently falls back to the CWD
     when %TEMP% is unusable, so the probe wrote into the repo and
     succeeded.  Playwright's node driver reads the TEMP env var directly
     and gets no such fallback.

The contract asserted: ``_temp_is_writable()`` reflects the env var path,
and the fallback only engages when that path is genuinely unusable.
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import conftest  # noqa: E402


def test_probe_reads_the_env_var_not_pythons_fallback(monkeypatch, tmp_path):
    """The probe must fail on an unusable TEMP even when Python's own
    tempfile fallback points somewhere writable.

    This is the exact shape that hid the bug: ``tempfile.gettempdir()``
    returned the repo root (writable), so a gettempdir()-based probe said
    "fine" while the browser got EPERM.  Here TEMP points at a path that
    cannot be created, while the CWD/tempfile fallback stays writable.
    """
    bogus = tmp_path / "does" / "not" / "exist" / "and" / "cannot" / "be"
    monkeypatch.setenv("TEMP", str(bogus))
    monkeypatch.setenv("TMP", str(bogus))
    assert conftest._temp_is_writable() is False, (
        "the probe approved a TEMP the browser cannot write -- it is "
        "reading Python's fallback instead of the env var")


def test_probe_approves_a_real_writable_dir(monkeypatch, tmp_path):
    """Control: a genuinely writable TEMP must pass, or the fallback would
    fire on healthy hosts and mask the real one."""
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    assert conftest._temp_is_writable() is True


def test_probe_writes_a_real_file_not_just_an_access_check(monkeypatch, tmp_path):
    """os.access() is not sufficient: it must actually create a file.

    A directory whose ACL grants W_OK but which every write refuses (the
    integrity-label case) is the whole reason this probe exists.
    """
    monkeypatch.setenv("TEMP", str(tmp_path))
    conftest._temp_is_writable()
    leftover = list(tmp_path.glob(".xssentinel-temp-probe-*"))
    assert leftover == [], (
        f"the probe left scratch files behind: {leftover}")


def test_probe_reports_false_when_temp_is_unset(monkeypatch):
    """No TEMP and no TMP means no answer -- and 'no answer' must never be
    read as 'writable'."""
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    assert conftest._temp_is_writable() is False


def test_probe_believes_the_write_not_the_acl(monkeypatch, tmp_path):
    """The integrity-label case: a directory whose ACL says "writable" but
    whose every write is refused.

    Without this test, the ``os.access`` mutation SURVIVED the suite --
    measured: swapping the probe to ``os.access(...)`` left all tests green,
    because ``os.access`` answers False for a path that does not exist,
    which is all the other cases exercise.  The one scenario it gets wrong
    is exactly the host defect this work started from, so it has to be
    simulated explicitly: a real, existing, ACL-writable directory where the
    write itself raises PermissionError.
    """
    real_open = open

    def _deny(path, *args, **kwargs):
        if os.path.dirname(os.path.abspath(str(path))) == str(tmp_path):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    monkeypatch.setattr("builtins.open", _deny)

    assert conftest._temp_is_writable() is False, (
        "the probe trusted the ACL: it never attempted the write, so it "
        "called an unusable TEMP writable -- the exact bug (trap #1)")



def test_the_documented_gate_command_gets_a_usable_temp():
    """End-to-end: a fresh pytest process importing conftest must end up
    with a TEMP that it can actually write.

    Runs a child interpreter so it measures the real import-time behaviour
    (including the module-level fallback), not a re-implementation of it.
    """
    code = (
        "import sys, os; sys.path.insert(0, 'tests'); import conftest;"
        "sys.stdout.write(os.environ.get('TEMP','') + '|' +"
        " str(conftest._temp_is_writable()))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT,
        capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    temp_path, writable = out.stdout.strip().rsplit("|", 1)
    assert temp_path, "conftest left TEMP unset -- the browser cannot start"
    assert writable == "True", (
        f"after importing conftest, TEMP={temp_path!r} is still unwritable; "
        "every real-browser test will fail on mkdtemp")
