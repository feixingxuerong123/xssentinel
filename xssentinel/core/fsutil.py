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

__all__ = ["secure_write_text", "chmod_private"]


def chmod_private(path) -> None:
    """Restrict ``path`` to owner read/write on POSIX; no-op on Windows."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def secure_write_text(path, text: str, encoding: str = "utf-8") -> str:
    """Write ``text`` and make the file owner-only on POSIX.

    Returns the path written (the caller usually wants it for logging).
    """
    with open(path, "w", encoding=encoding) as f:
        f.write(text)
    chmod_private(path)
    return str(path)
