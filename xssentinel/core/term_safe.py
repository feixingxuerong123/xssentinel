"""Terminal-sink sanitization (Phase 323).

Threat model (dalfox v3.2.4 #1513 parity, same class of fix): the scanned
target controls part of what the scanner prints to the operator's terminal --
reflected strings, discovered URLs (redirect ``Location:``, link hrefs,
worker/websocket URLs), discovered parameter names, error-page text.  A
response carrying ANSI/VT escape sequences can rewrite terminal lines that
already carry operator-facing verdicts: move the cursor, clear the screen,
overwrite a ``[+] confirmed`` line with a ``[-] clean`` line, or forge a
whole progress bar.  The bytes have no semantic value for the operator, so
the terminal SINK strips them.

What is deliberately NOT stripped:

* stored findings / reports keep the raw bytes -- a PoC must replay the real
  param name, so sanitization happens only where the string is rendered to a
  terminal, never where it is persisted (the HTML report is already
  escape-first by construction, Phase 176);
* the project itself emits no ANSI colors (measured: no ``\\x1b`` producer
  anywhere in the package), so a strip can never eat the scanner's own
  formatting.

Two consumption shapes:

* :func:`strip_ansi` for one-off values;
* :class:`SanitizedStream` for choke points (the logging stream handler in
  :mod:`xssentinel.core.logger`, the progress bar in
  :mod:`xssentinel.core.progress`) so every log record and progress line is
  sanitized once, at the boundary, instead of at each of the dozens of
  ``print``/``_log`` call sites that interpolate target-derived data.

:func:`safe_print` is the drop-in replacement for ``print`` at the raw call
sites that carry target-derived data; sites that only print the scanner's
own counters/flags stay plain ``print`` -- the rule is data provenance, not
"sanitize everything".
"""
from __future__ import annotations

import re

__all__ = ["strip_ansi", "safe_print", "SanitizedStream",
           "install_cli_print_guard", "uninstall_cli_print_guard"]

# ESC-initiated and C1 sequences, in the order a terminal's state machine
# meets them.  Alternation is ordered: CSI/OSC/DCS match their fixed second
# byte before the generic ESC branch could claim it.  The generic branch is
# ECMA-48's ESC grammar (optionally-escaped intermediates then a final
# byte in 0x30-0x7E), so ESC 7 (DECSC), ESC (0 (charset) and ESC M (RI)
# are all matched whole.
_ANSI_RE = re.compile(
    r"\x1b(?:"                     # ESC ...
    r"\[[0-?]*[ -/]*[@-~]"         # CSI:  ESC [ params intermediates final
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)?"   # OSC:  ESC ] payload (BEL | ST)?
    r"|P[^\x1b]*(?:\x1b\\)?"       # DCS:  ESC P payload ST?
    r"|[ -/]*[0-~]"                # generic ESC: [intermediates] final
    r")"
)
#: 8-bit CSI (U+009B): identical grammar to ESC[ in control-capable
#: terminals, stripped with the same parameter/final span so the WHOLE
#: sequence goes, not just the lead byte.
_C1_CSI_RE = re.compile("\x9b[0-?]*[ -/]*[@-~]")
#: Remaining C1 control characters (U+0080-U+009F): no display value for
#: the operator, stripped individually.
_C1_RE = re.compile("[\x80-\x9f]")


def strip_ansi(value):
    """Return ``value`` with terminal control sequences removed.

    Strips ESC-initiated sequences (CSI/OSC/DCS/two-char), lone trailing
    ESC bytes and the Unicode C1 control block from ``str`` inputs;
    anything else (ints, lists, dicts interpolated by the caller's f-string
    formatting) passes through untouched -- the f-string has already
    rendered it to text by the time it reaches here.
    """
    if not isinstance(value, str):
        return value
    cleaned = _ANSI_RE.sub("", value).replace("\x1b", "")
    cleaned = _C1_CSI_RE.sub("", cleaned)
    return _C1_RE.sub("", cleaned)


#: Captured before any guard runs: :func:`safe_print` must call the REAL
#: ``print``, not whatever ``builtins.print`` currently points to -- the
#: CLI guard sets ``builtins.print = safe_print``, so a bare ``print()``
#: in here would recurse into itself forever.
_ORIGINAL_PRINT = print


def safe_print(*args, **kwargs):
    """``print`` with every string argument passed through
    :func:`strip_ansi`.  Keyword arguments (``sep``/``end``/``file``/
    ``flush``) are forwarded unchanged.
    """
    _ORIGINAL_PRINT(*(strip_ansi(a) for a in args), **kwargs)


def install_cli_print_guard() -> None:
    """Replace :data:`builtins.print` with :func:`safe_print` in this process.

    Called ONCE from the CLI entry point (``python -m xssentinel``) after
    argument parsing, never on package import, never in the MCP stdio mode
    (there stdout is a JSON-RPC protocol channel whose payload values must
    stay byte-exact -- stray prints in that mode are a protocol bug the
    MCP server already forbids).

    Why patch instead of editing call sites: the console carries
    target-derived data at ~75 ``print`` sites across the layer/CLI
    modules (discovered URLs, param names, sink descriptions, server
    error text) and the count grows every phase -- a sink guard covers
    current and future sites with one seam.  The scanner itself emits no
    ANSI (measured: no ``\\x1b`` producer in the package), so the guard
    cannot alter the scanner's own formatting; subprocess harnesses that
    capture CLI stdout read verdicts from report FILES (benchmark/
    adapters.py), not from these prints.

    Library embedding is unaffected: the patch lives only inside a CLI
    process.  A test can undo it by restoring
    ``builtins.print`` captured before calling the CLI entry.
    """
    import builtins
    builtins.print = safe_print  # noqa: A001  (deliberate, documented)


def uninstall_cli_print_guard() -> None:
    """Undo :func:`install_cli_print_guard`.

    The CLI entry wraps the guard around ``main()`` with try/finally so a
    test that drives ``main()`` in-process cannot leak the patch into the
    whole pytest process.  Always restores the pristine ``print``
    captured at import time; a no-op if the guard is not installed.
    """
    import builtins
    if builtins.print is safe_print:
        builtins.print = _ORIGINAL_PRINT



class SanitizedStream:
    """Wrap a text stream so everything written through it is ANSI-free.

    Used at the two terminal choke points (log handler, progress bar).  It
    is a write-side wrapper only: ``isatty``/``fileno`` delegate to the inner
    stream so TTY-detection (progress bar rendering mode) keeps working.
    """

    def __init__(self, inner):
        self._inner = inner

    def write(self, s) -> int:
        return self._inner.write(strip_ansi(s))

    def writelines(self, lines) -> None:
        self._inner.writelines(strip_ansi(s) for s in lines)

    def flush(self) -> None:
        self._inner.flush()

    def isatty(self) -> bool:
        try:
            return bool(self._inner.isatty())
        except (AttributeError, ValueError, OSError):
            return False

    def fileno(self):
        return self._inner.fileno()

    def writable(self) -> bool:
        return True
