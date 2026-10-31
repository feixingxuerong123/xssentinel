"""Private-by-default artifact writes (Phase 326).

Report artifacts carry target URLs, discovered parameters and live
payloads; on a shared host they are the scanner's output of record and
should not be world readable.  A permissive umask is the norm, not an
exception, so POSIX writes are chmod-ed to 0600 explicitly after the
content lands.

Windows has no POSIX mode bits: ``os.chmod`` there only toggles the
read-only flag, and access control is the operator's ACLs.  Skipping it
is the honest behaviour -- pretending to secure what the platform does
not model would be worse than doing nothing.
"""
from __future__ import annotations

import os
import tempfile

__all__ = ["secure_write_text", "chmod_private", "ensure_writable_temp"]


def chmod_private(path) -> None:
    """Restrict ``path`` to owner read/write on POSIX; no-op on Windows."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _can_write(directory: str) -> bool:
    """Whether a real file can be created and removed in ``directory``.

    ``os.access(W_OK)`` is deliberately not used: on Windows it answers the
    ACL and cannot see an integrity label, which is exactly the case that
    produced this bug (a Low-integrity process tree, an ACL that says yes, a
    write that fails).  Only an actual create/delete answers the question.
    """
    probe = os.path.join(directory, ".xssentinel-write-probe")
    try:
        os.makedirs(directory, exist_ok=True)
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("")
        os.unlink(probe)
        return True
    except (OSError, ValueError):
        # ValueError: a path with an embedded null or an otherwise illegal
        # name -- a caller-supplied TMPDIR is not trusted input.  The
        # function's contract is a boolean, never an exception.
        return False


def ensure_writable_temp() -> str | None:
    """Point the process temp dir somewhere writable; return it if moved.

    Phase 347.  Measured on this host: the workspace tree carries a Low
    mandatory integrity label, so ``%TEMP%`` is not writable by the scanner
    process.  ``tempfile.gettempdir()`` does not fail in that case -- it falls
    back to the *current working directory*, and two 0-byte ``tmpXXXXXX``
    files appeared in the repository root after every single scan (verified:
    two per run; none when TEMP was pointed at a writable directory).  A
    security tool must not leave droppings in the operator's working
    directory, and "the dependency that calls mkstemp" is not ours to fix --
    the process-wide fallback is.

    Preference order: keep the system temp dir when it is writable (the
    normal case, no change), else ``~/.cache/xssentinel/tmp``, else
    ``<cwd>/.xssentinel-tmp``.  Child processes read ``TEMP``/``TMP``
    directly (the Playwright node driver does), so the environment variables
    are set as well as ``tempfile.tempdir``.

    Returns the directory now in effect when it had to move, ``None`` when
    nothing changed.  Never raises: a scan must not fail because a temp
    directory could not be prepared.
    """
    current = tempfile.gettempdir()
    # `gettempdir()` silently falls back to the CWD when the environment temp
    # dir is not writable, so "current is writable" proves nothing -- the CWD
    # is exactly the directory that must not be used.  The first version of
    # this function made that mistake and the leak survived it (measured:
    # files still appeared after the "fix").  The environment variable is the
    # only statement of intent available, so it is checked too.
    env_temp = (os.environ.get("TEMP") or os.environ.get("TMP")
                or os.environ.get("TMPDIR"))
    if not _is_cwd(current) and _can_write(current):
        return None

    # The environment temp dir may still be fine even when gettempdir() chose
    # otherwise; prefer it over inventing a location.
    if env_temp and not _is_cwd(env_temp) and _can_write(env_temp):
        if _apply_temp(env_temp):
            return env_temp
        return None

    for directory in (
            os.path.join(os.path.expanduser("~"), ".cache", "xssentinel", "tmp"),
            os.path.join(os.getcwd(), ".xssentinel-tmp")):
        if _is_cwd(directory) or directory == current:
            continue
        if not _can_write(directory):
            continue
        if _apply_temp(directory):
            return directory
    return None


def _is_cwd(directory: str) -> bool:
    """Whether ``directory`` is the current working directory (or inside it)."""
    try:
        d = os.path.normcase(os.path.realpath(directory))
        c = os.path.normcase(os.path.realpath(os.getcwd()))
    except (OSError, ValueError):
        return False
    return d == c


def _apply_temp(directory: str) -> bool:
    """Point tempfile and the child-process env vars at ``directory``."""
    try:
        tempfile.tempdir = directory
        for var in ("TEMP", "TMP", "TMPDIR"):
            os.environ[var] = directory
        return True
    except Exception:
        return False


def secure_write_text(path, text: str, encoding: str = "utf-8") -> str:
    """Write ``text`` and make the file owner-only on POSIX.

    Returns the path written (the caller usually wants it for logging).
    """
    with open(path, "w", encoding=encoding) as f:
        f.write(text)
    chmod_private(path)
    return str(path)
