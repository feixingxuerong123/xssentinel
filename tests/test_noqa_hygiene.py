"""Static gate: every F401 suppression in shipped code must carry a reason.

Bug family this locks (found 2026-10-01):

``pyproject.toml``'s ``[tool.ruff.lint.per-file-ignores]`` comment asserted that
the scanner Mixin imports "are now annotated with inline ``# noqa: F401``
comments (with reasons)".  Measured against the tree: **47 F401 suppressions,
40 of them bare**.  The convention existed only inside a config comment -- the
same "docs assert something the code never did" drift that let the 313-entry
lint baseline accumulate in the first place.  A bare suppression also survives
review precisely because it *looks* deliberate.

Why F401 and not every rule:

* Unused imports were the bulk of the 313-entry baseline this project just
  cleared, and a bare ``# noqa: F401`` is the cheapest way to reintroduce one
  unnoticed.  It is the finding class that actually rots.
* ``E402`` (import not at top of file) is deliberately exempt: structural,
  visible at a glance, and it cannot accumulate silently the way an unused
  import does.  Forcing a reason on ~60 of them would be noise.
* Suppressions for rules outside ``select = ["E", "F", "W"]`` are exempt too.
  ``N802`` on ``do_GET``/``do_POST`` handlers and ``BLE001`` on broad excepts
  are intent markers for rules the project may enable later; deleting them
  would throw away comments like "reaper never dies".  Dead-but-documented
  beats gone.

Scope: ``xssentinel/`` and ``tests/``.  ``benchmark/``, ``dev/``, ``range3/``
and ``range4/`` are tooling and ranges, not shipped code.
"""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNED = [os.path.join(ROOT, "xssentinel"), os.path.join(ROOT, "tests")]

# The suppression marker (hash omitted below so ruff does not read this very
# comment as a real directive), followed by a comma-separated code list, then
# whatever is left on the line.  The leftover is the reason; empty = "bare".
NOQA = re.compile(
    r"#\s*noqa:\s*(?P<codes>[A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*)(?P<rest>.*)$")


def _iter_py(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        if "__pycache__" in dirpath:
            continue
        for name in filenames:
            if name.endswith(".py") and ".bak" not in name:
                yield os.path.join(dirpath, name)


def test_f401_suppressions_carry_a_reason():
    """A bare ``# noqa: F401`` is how an unused import comes back quietly."""
    offenders = []
    for root in SCANNED:
        for path in _iter_py(root):
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    m = NOQA.search(line)
                    if not m:
                        continue
                    if "F401" not in m.group("codes"):
                        continue
                    if m.group("rest").strip():
                        continue
                    rel = os.path.relpath(path, ROOT)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "bare `# noqa: F401` -- say WHY the import is unused (re-export, Mixin "
        "runtime reference, optional-dependency probe).  Without a reason a "
        "genuine unused import is indistinguishable from an intentional one."
        "\n  " + "\n  ".join(offenders))
