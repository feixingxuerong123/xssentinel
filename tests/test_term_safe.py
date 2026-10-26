# -*- coding: utf-8 -*-
"""Phase 323: terminal-sink sanitization (ANSI/VT escape sequences).

Threat model (dalfox v3.2.4 #1513 parity): the scanned target controls
part of what reaches the operator's terminal -- reflected strings,
discovered URLs (redirect Location, worker/ws URLs), param names, server
error text.  A response carrying ``\\x1b[2J\\x1b[H`` could clear the screen
and rewrite a ``[+] confirmed`` line into ``[-] clean``; ``\\x9b`` (C1 CSI)
does the same in 8-bit-control terminals.  The sink strips them; the
STORED report keeps the raw bytes (a PoC must replay the real name).
"""
from __future__ import annotations

import io
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import term_safe as ts                     # noqa: E402
from xssentinel.core.logger import configure_logging           # noqa: E402
from xssentinel.core.progress import ConsoleProgress           # noqa: E402


EVIL_URL = "http://t/\x1b[2J\x1b[H\x1b[1A[-] clean, nothing found"
C1_URL = "http://t/\x9b2Jfake"


# ---------------------------------------------------------------------------
# 1. the stripper
# ---------------------------------------------------------------------------
def test_strip_ansi_removes_csi_sequences():
    assert ts.strip_ansi("\x1b[2J\x1b[Hhello") == "hello"
    assert ts.strip_ansi("a\x1b[31;1;42mb\x1b[0m") == "ab"
    # parameter bytes 0x30-0x3F include '?' (private DEC modes)
    assert ts.strip_ansi("\x1b[?25lx") == "x"


def test_strip_ansi_removes_osc_and_dcs_sequences():
    # OSC with BEL terminator (window title -- classic spoof surface)
    assert ts.strip_ansi("\x1b]0;fake verdict\x07ok") == "ok"
    # OSC with ST terminator
    assert ts.strip_ansi("\x1b]8;;http://evil\x1b\\link") == "link"
    # DCS with ST
    assert ts.strip_ansi("\x1bP1$r\x1b\\res") == "res"
    # unterminated OSC: payload is all attacker bytes, drop to end
    assert ts.strip_ansi("x\x1b]0;evil") == "x"


def test_strip_ansi_removes_lone_esc_and_c1_controls():
    # lone trailing ESC
    assert ts.strip_ansi("abc\x1b") == "abc"
    # two-char escape (DECSC)
    assert ts.strip_ansi("\x1b7saved") == "saved"
    # C1 control block (U+009B acts as CSI in 8-bit-control terminals)
    assert ts.strip_ansi(C1_URL) == "http://t/fake"
    # plain DEL stays -- it is not a control *sequence*
    assert ts.strip_ansi("keep \x7f") == "keep \x7f"


def test_strip_ansi_preserves_operator_text_and_passthrough():
    zh = "[+] 已确认 XSS via 参数 q"
    assert ts.strip_ansi(zh) == zh
    # non-str passthrough unchanged
    assert ts.strip_ansi(7) == 7
    assert ts.strip_ansi(None) is None
    assert ts.strip_ansi(["\x1b[2J", "ok"]) == ["\x1b[2J", "ok"]


def test_the_scanner_corpus_never_depends_on_ansi():
    """strip_ansi must not mangle a payload: stored payloads keep raw bytes,
    and the strip only touches the terminal rendering."""
    payload = "<script>alert(1)</script>"
    assert ts.strip_ansi(payload) == payload


# ---------------------------------------------------------------------------
# 2. safe_print + the CLI guard
# ---------------------------------------------------------------------------
def test_safe_print_strips_arguments(capsys):
    ts.safe_print(f"[+] {EVIL_URL}")
    out = capsys.readouterr().out
    # the cursor-control capability is gone -- that is the attack; the
    # attacker's TEXT is not (over-stripping would hide operator data)
    assert "\x1b" not in out and "\x9b" not in out
    assert "http://t/" in out
    assert "[-] clean, nothing found" in out, \
        "post-strip the payload text stays VISIBLE inline garbage, " \
        "not silently rewritten over the real verdict line"


def test_cli_print_guard_sanitizes_the_process_print(capsys):
    import builtins
    original = builtins.print
    try:
        ts.install_cli_print_guard()
        builtins.print(f"[+] {EVIL_URL}")
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "[+] http://t/[-] clean, nothing found" in out
    finally:
        builtins.print = original


def test_guard_is_recursion_safe(capsys):
    """safe_print must call the ORIGINAL print, not the patched one -- the
    guard sets builtins.print = safe_print, so a bare print() in safe_print
    would recurse forever.  Install twice to also pin idempotence."""
    import builtins
    original = builtins.print
    try:
        ts.install_cli_print_guard()
        ts.install_cli_print_guard()
        builtins.print("[+] survives double install")
        assert "[+] survives double install" in capsys.readouterr().out
    finally:
        builtins.print = original


# ---------------------------------------------------------------------------
# 3. the choke points: logging handler and progress renderer
# ---------------------------------------------------------------------------
def test_logging_stream_strips_target_data():
    buf = io.StringIO()
    configure_logging("debug", stream=buf)
    logging.getLogger("xssentinel.test").debug(f"reflected: {EVIL_URL}")
    buf.flush()
    assert "\x1b" not in buf.getvalue()
    assert "reflected: http://t/" in buf.getvalue()


def test_progress_renderer_strips_finding_urls():
    buf = io.StringIO()
    prog = ConsoleProgress(stream=buf, show_bar=False)
    prog.on_start(1)
    prog.on_finding({"severity": "high", "type": "reflected",
                     "url": EVIL_URL})
    out = buf.getvalue()
    # escape bytes are gone: the bar cannot be repositioned/rewritten
    assert "\x1b" not in out
    assert "high" in out and "reflected" in out
    # ...while the finding line itself stays visible
    assert "[+] high" in out


def test_sanitized_stream_delegates_isatty():
    class Tty(io.StringIO):
        def isatty(self):
            return True

    wrapped = ts.SanitizedStream(Tty())
    assert wrapped.isatty() is True
    wrapped.write("ok")
    assert wrapped.writable() is True


# ---------------------------------------------------------------------------
# 4. the guard's scope: installed by main(), removed on every exit path,
#    never installed for --mcp (protocol channel)
# ---------------------------------------------------------------------------
def test_guard_is_scoped_to_the_cli_call(capsys):
    """In-process drivers (tests) must not leak a patched print: main()
    installs the guard and removes it on the way out -- even on the
    SystemExit argparse raises for ``--help``, which is the cheapest
    full install->finally->uninstall path with zero network."""
    import builtins
    import pytest
    from xssentinel import __main__ as cli
    original = builtins.print
    try:
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        assert builtins.print is original, \
            "main() leaked the patched print into the host process"
    finally:
        builtins.print = original


def test_mcp_mode_leaves_print_alone():
    """--mcp uninstalls the guard BEFORE serving: stdout is a JSON-RPC
    protocol channel there and its payload bytes must stay exact.  The
    wiring (not just the helpers) is pinned by reading the entry source
    -- same discipline as the async call-site guards."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "xssentinel", "__main__.py")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    # the wrapper installs before the impl and uninstalls after
    assert "install_cli_print_guard()" in src
    assert "uninstall_cli_print_guard()" in src
    # the mcp branch uninstalls BEFORE handing over to the protocol server
    mcp_pos = src.index('getattr(args, "mcp", False)')
    uninstall_pos = src.index("uninstall_cli_print_guard()", mcp_pos)
    serve_pos = src.index("return _mcp_serve()", mcp_pos)
    assert uninstall_pos < serve_pos, \
        "--mcp must drop the guard before stdout becomes the protocol"
