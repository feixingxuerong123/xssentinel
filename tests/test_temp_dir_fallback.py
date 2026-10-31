# -*- coding: utf-8 -*-
"""Phase 347: a scan must not leave temp files in the operator's directory.

Why this file exists
--------------------
Measured on this host: every single scan left two 0-byte ``tmpXXXXXX`` files
in the current working directory, and never removed them.  The producer is a
dependency calling ``tempfile.mkstemp`` -- not our code -- but the reason it
lands in CWD is: this workspace tree carries a Low mandatory integrity label,
``%TEMP%`` is not writable by the scanner process, and ``tempfile.gettempdir()``
does not fail in that case.  It falls back to the current directory.

Verified before fixing (the fix is only worth its risk if the diagnosis is):
two files per run; none when ``TEMP`` was pointed at a writable directory.

So the gate is: ``ensure_writable_temp()`` either leaves everything alone
(the normal host) or moves the process temp dir somewhere writable, and it
reports the move.  What it must never do is raise -- a scan cannot fail
because a temp directory could not be prepared.

Why ``os.access`` is not the probe
----------------------------------
On Windows ``os.access(W_OK)`` answers the ACL and cannot see an integrity
label: it says "writable" about the exact directory that rejected the write.
The probe therefore creates and deletes a real file.
"""
import os
import tempfile

import sys
sys.path.insert(0, ".")

from xssentinel.core.fsutil import _can_write, ensure_writable_temp


def _reset_temp(monkeypatch):
    """Isolate the process-wide tempfile state between tests."""
    monkeypatch.setattr(tempfile, "tempdir", None)
    for var in ("TEMP", "TMP", "TMPDIR"):
        monkeypatch.delenv(var, raising=False)


# -- probe -----------------------------------------------------------------

def test_can_write_true_for_a_real_directory(tmp_path):
    assert _can_write(str(tmp_path)) is True


def test_can_write_creates_missing_directories(tmp_path):
    """Candidate dirs (``~/.cache/xssentinel/tmp``) usually do not exist yet."""
    target = tmp_path / "a" / "b"
    assert _can_write(str(target)) is True
    assert target.is_dir()


def test_can_write_false_for_an_illegal_path():
    """An embedded null is the portable "this can never work" path.

    chmod-based fixtures are useless here: on Windows mode bits do not model
    access, which is the whole reason this module exists.
    """
    assert _can_write("\0invalid") is False


def test_can_write_leaves_no_probe_behind(tmp_path):
    assert _can_write(str(tmp_path)) is True
    assert list(tmp_path.iterdir()) == []


# -- control flow ----------------------------------------------------------
#
# The probe above is tested for real.  The tests below stub it, because the
# condition it detects on this host -- an ACL that says yes and an integrity
# label that says no -- cannot be constructed from a test.  The stub is at the
# probe boundary, so the branch under test (which directory gets chosen, what
# gets set, what gets returned) is the real code.

def _probe_says(fake_current: str, writable_suffixes=("cache", "xssentinel-tmp")):
    def _fake(directory: str) -> bool:
        if directory == fake_current:
            return False
        return any(s in directory for s in writable_suffixes)
    return _fake


def test_writable_temp_is_left_alone(tmp_path, monkeypatch):
    """The normal host: no change, and nothing printed by the caller."""
    _reset_temp(monkeypatch)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    assert ensure_writable_temp() is None
    assert tempfile.tempdir is None, "a healthy temp dir must not be rewritten"


def test_unwritable_temp_is_moved_and_reported(monkeypatch, tmp_path):
    """A temp dir that cannot be written must be replaced, not tolerated."""
    _reset_temp(monkeypatch)
    fake_current = str(tmp_path / "readonly-temp")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: fake_current)
    monkeypatch.setattr("xssentinel.core.fsutil._can_write",
                        _probe_says(fake_current))
    monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / "home"))

    moved = ensure_writable_temp()
    assert moved, "an unwritable temp dir must produce a replacement"
    assert tempfile.tempdir == moved
    assert os.environ["TEMP"] == moved
    assert os.environ["TMP"] == moved
    assert os.environ["TMPDIR"] == moved


def test_falls_back_to_cwd_when_home_is_unusable(monkeypatch, tmp_path):
    """Second candidate: the run must still work with no usable home dir."""
    _reset_temp(monkeypatch)
    fake_current = str(tmp_path / "readonly-temp")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: fake_current)
    monkeypatch.setattr("xssentinel.core.fsutil._can_write",
                        _probe_says(fake_current, ("xssentinel-tmp",)))
    monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / "home"))
    monkeypatch.setattr(os, "getcwd", lambda: str(tmp_path / "work"))

    moved = ensure_writable_temp()
    assert moved and moved.endswith(".xssentinel-tmp")


def test_cwd_fallback_is_not_accepted_as_a_temp_dir(monkeypatch, tmp_path):
    """The exact shape that defeated the first version of this fix.

    ``gettempdir()`` had already fallen back to the CWD, the CWD was
    writable, so the probe said "healthy" and nothing moved -- the leak
    survived the fix.  A writable CWD must count as "needs moving", not as
    "fine".
    """
    _reset_temp(monkeypatch)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(work))
    monkeypatch.setattr(os, "getcwd", lambda: str(work))
    monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / "home"))

    moved = ensure_writable_temp()
    assert moved is not None, "a CWD temp dir is the bug, not the healthy case"
    assert not str(moved).startswith(str(work)), "must not stay in the CWD"


def test_writable_env_temp_is_preferred_over_inventing_one(monkeypatch, tmp_path):
    """When TEMP is fine but gettempdir() fell back anyway, use TEMP."""
    _reset_temp(monkeypatch)
    work = tmp_path / "work"
    work.mkdir()
    env_dir = tmp_path / "sys-temp"
    env_dir.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(work))
    monkeypatch.setattr(os, "getcwd", lambda: str(work))
    monkeypatch.setenv("TEMP", str(env_dir))

    assert ensure_writable_temp() == str(env_dir)
    assert tempfile.tempdir == str(env_dir)


def test_never_raises_even_when_every_candidate_fails(monkeypatch):
    """The contract is "best effort"; a scan must not die here."""
    _reset_temp(monkeypatch)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "\0broken")
    monkeypatch.setattr("os.path.expanduser", lambda p: "\0also-broken")
    monkeypatch.setattr(os, "getcwd", lambda: "\0cwd-broken")
    assert ensure_writable_temp() is None


def test_reports_none_when_it_cannot_help(monkeypatch):
    """No silent success: an unmovable temp dir returns None, not a lie."""
    _reset_temp(monkeypatch)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "\0broken")
    monkeypatch.setattr("xssentinel.core.fsutil._can_write", lambda d: False)
    assert ensure_writable_temp() is None
