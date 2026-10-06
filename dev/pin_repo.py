r"""sys.path must be pinned before importing xssentinel, or the probe
measures a DIFFERENT checkout.

This host has an editable install of another xssentinel tree
(`D:/op/xssentinel`, installed via `__editable__.xssentinel-1.2.0.pth` in
C:/Python39/Lib/site-packages).  Python puts the SCRIPT's directory first
on sys.path, so a probe living in dev/ imports whichever tree the
finder resolves -- and it resolved to D:/op, silently.

The symptom is nasty: the probe fails with `ImportError: cannot import
name 'get_shared_browser'` for a symbol that plainly exists in the repo
being edited.  Easy to misread as "the code under test is broken" --
which is exactly how it was misread before this helper existed.

Tracked (no `_` prefix) on purpose: every probe in dev/ hits this, and a
helper the next person has to rediscover is a helper they will instead
work around by hand.  Same convention as dev/fetch_range5_vendor.py --
reproducible forensics belong in version control.

Usage, right after the sys.path shim and BEFORE any xssentinel import:

    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from pin_repo import pin
    pin()
"""
from __future__ import annotations

import os
import sys

#: The repository root (dev/ -> repo root).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pin() -> str:
    """Put this repo first on sys.path and return the resolved package
    directory, raising if it is not ours."""
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    import xssentinel
    resolved = os.path.dirname(os.path.abspath(xssentinel.__file__))
    expected = os.path.join(REPO_ROOT, "xssentinel")
    if os.path.normcase(resolved) != os.path.normcase(expected):
        raise RuntimeError(
            f"xssentinel resolved to {resolved}, expected {expected}. "
            f"Another checkout shadows this one (editable install?). "
            f"sys.path[0] was {sys.path[0]!r}.")
    return resolved
