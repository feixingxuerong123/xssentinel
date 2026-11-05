# -*- coding: utf-8 -*-
"""Phase 360: the CLI's output and input contracts, in one place.

Two contracts kept getting re-implemented in different modules:

* **Where human text goes.**  Normally stdout (byte-for-byte unchanged from
  1.4.1); when ``-o -`` turns stdout into a machine-readable report channel,
  it is stderr.  Phase 359 pinned this inside ``_main_impl`` and guarded its
  prints with an AST assertion -- but ``cli_runner`` / ``cli_commands`` still
  had 76 bare prints, and a measured ``-o -`` run with ``--login-token``,
  ``--ai-report``, ``--fuzz``, ``--discover`` or a spec import put those
  lines into the report stream.  Every CLI print now names ``human()``; the
  guard walks all three modules so a future line cannot re-pollute stdout.

  This is a per-invocation value, not a ``sys.stdout`` patch: ``main()``
  resets it in a ``finally``, so an in-process test driver that calls
  ``main(argv)`` twice never inherits the previous run's stream.

* **How operator-supplied text files are decoded.**  Phase 359 wrote it for
  ``--batch`` / ``--batch-stdin``; ``--config``, ``batch_urls`` and
  ``custom_payloads`` still used bare ``encoding="utf-8"``, so a UTF-8 BOM
  made ``Config.load`` silently return an EMPTY config (measured: "No target
  specified" instead of an error) and a GBK file raised an uncaught
  ``UnicodeDecodeError`` with a traceback.  One decoder, one honest error.
"""
from __future__ import annotations

import sys
from typing import IO, TextIO

_human_stream: TextIO | None = None


def set_human_stream(stream: TextIO) -> None:
    """Bind the operator-facing stream for the duration of one CLI call."""
    global _human_stream
    _human_stream = stream


def reset_human_stream() -> None:
    """Restore the default (stdout).  Called from ``main()``'s finally."""
    global _human_stream
    _human_stream = None


def human() -> TextIO:
    """The stream for human-facing lines: stderr in ``-o -`` mode, else stdout."""
    return _human_stream if _human_stream is not None else sys.stdout


# ---------------------------------------------------------------------------
# Input decoding
# ---------------------------------------------------------------------------

def decode_input_bytes(data: bytes) -> tuple[str, str | None]:
    """Decode an operator text file/pipe the way Windows pipelines emit it.

    Accepts UTF-8 (with or without BOM), UTF-16 (BOM) and GB18030, in that
    order.  Returns ``(text, error)``; ``error`` is a human message rather
    than an exception so a bad file becomes an honest usage error (rc=2),
    never a traceback.  Shared by batch URL lists, ``--config``,
    ``batch_urls`` and ``custom_payloads``.
    """
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), None
        except UnicodeDecodeError as e:
            return "", f"UTF-16 decode failed: {e}"
    for enc in ("utf-8-sig", "gb18030"):
        try:
            return data.decode(enc), None
        except UnicodeDecodeError:
            continue
    return "", ("input is not valid UTF-8, GB18030 or UTF-16 text; "
                "re-save the file as UTF-8")


def read_text_file(path: str) -> tuple[str, str | None]:
    """Read an operator text file with the shared decoder.

    Returns ``(text, error)``.  A missing/unreadable file is reported the
    same way as an undecodable one, so callers have one failure shape.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return "", f"cannot read {path}: {e}"
    text, err = decode_input_bytes(data)
    if err:
        return "", f"{path}: {err}"
    return text, None


def clean_batch_lines(text: str) -> list[str]:
    """Strip BOM/CRLF/blank lines and ``#`` comments from decoded input."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff").strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# ---------------------------------------------------------------------------
# Report channel
# ---------------------------------------------------------------------------

class OutputPipeClosed(BrokenPipeError):
    """The stdout consumer went away (``| head``, a closed pipe, a dead IDE).

    Raised by ``write_report_frame`` instead of leaking an OSError into the
    per-target error handler: that handler used to mark every remaining
    target as "scan failed" and exit 3, which lied about a scan that was
    fine -- only its reader had left.
    """


def write_report_frame(out: str, fmt: str, stream: IO | None = None) -> None:
    """Emit ONE machine-readable report frame on stdout as UTF-8 BYTES.

    ``-o -`` makes stdout a protocol channel: no human summary, no Windows
    console codepage.  JSON is compacted to one line (batch = JSONL).  When
    a binary buffer is unavailable (an injected ``StringIO`` in tests/IDEs),
    the text fallback escapes non-ASCII so a cp936 console cannot raise
    ``UnicodeEncodeError`` and drop the frame -- the same lesson as the
    Phase 358 stdio channel.
    """
    sink = stream if stream is not None else sys.stdout

    if fmt == "json":
        try:
            import json as _json
            out = _json.dumps(_json.loads(out), ensure_ascii=False) + "\n"
        except (ValueError, TypeError):
            out = out.rstrip("\n") + "\n"
    elif not out.endswith("\n"):
        out += "\n"

    buf = getattr(sink, "buffer", None)
    try:
        if buf is not None:
            buf.write(out.encode("utf-8"))
            buf.flush()
        else:
            # Text-only sink: ASCII escapes keep the frame lossless on a
            # legacy codepage; the JSON consumer still sees real Unicode
            # after parsing.
            sink.write(out.encode("ascii", "backslashreplace").decode("ascii"))
            sink.flush()
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        raise OutputPipeClosed(str(e)) from e
