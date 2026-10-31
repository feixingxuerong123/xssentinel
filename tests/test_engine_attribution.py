"""Engine attribution: the artifact must be able to say which engine ran.

`--async` with aiohttp missing used to fall back to the sync engine with one
WARNING on stderr and then write a report that was byte-identical to a real
async run -- same fields, same exit code 0.  Nothing in the deliverable could
answer "did this pipeline really use --async?", which made two comparisons
silently invalid: a sync result measured against an async baseline, and a CI
job that believed it was exercising the async path while running the sync one.

Four pieces of the fix are locked here:

  1. every report carries ``engine`` (sync or async),
  2. a degraded run also carries ``engine_fallback_reason``,
  3. the human deliverable shows the fallback as a banner, not a buried field,
  4. ``--require-async`` refuses to degrade (exit 3) instead of pretending.
"""
from __future__ import annotations

import argparse
import json

import pytest

from xssentinel import cli_runner
from xssentinel.core import report
from xssentinel.core.scanner import Scanner


def _args(**kw) -> argparse.Namespace:
    """Namespace carrying only what the async-availability path reads."""
    base = {"require_async": False, "async_mode": False, "verbose": False}
    base.update(kw)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# 1-2. The machine-readable report
# ---------------------------------------------------------------------------
def test_build_json_carries_the_engine():
    out = json.loads(report.build_json([], "http://t/", {"engine": "async"}))
    assert out["engine"] == "async"
    # A clean run has nothing to explain; the key exists so consumers never
    # have to distinguish "absent" from "no fallback happened".
    assert out["engine_fallback_reason"] is None


def test_build_json_carries_the_fallback_reason():
    meta = {"engine": "sync",
            "engine_fallback_reason": "aiohttp is not installed"}
    out = json.loads(report.build_json([], "http://t/", meta))
    assert out["engine"] == "sync"
    assert out["engine_fallback_reason"] == "aiohttp is not installed"


def test_build_json_engine_key_is_present_even_without_meta():
    """Old callers pass no engine; the field must still be there, as null.

    `build_json` is called by the API server and by tests with hand-built meta
    dicts.  A missing key would push the "which engine?" question back onto
    every consumer.
    """
    out = json.loads(report.build_json([], "http://t/", {}))
    assert "engine" in out
    assert out["engine"] is None


# ---------------------------------------------------------------------------
# 3. The human deliverable
# ---------------------------------------------------------------------------
def test_html_report_shows_the_fallback_banner():
    html = report.build_html(
        [], "http://t/",
        {"engine": "sync", "engine_fallback_reason": "aiohttp is not installed"})
    assert "ENGINE FALLBACK" in html
    assert "aiohttp is not installed" in html


def test_html_report_states_the_engine_in_the_meta_line():
    html = report.build_html([], "http://t/", {"engine": "async"})
    assert "Engine: async" in html


def test_html_report_stays_quiet_without_a_fallback():
    """A banner on every sync report would be noise and train readers to skip
    the banner area -- which is where the real warnings live."""
    html = report.build_html([], "http://t/", {"engine": "sync"})
    assert "ENGINE FALLBACK" not in html
    assert "Engine: sync" in html


# ---------------------------------------------------------------------------
# 4. Attribution through the report writer
# ---------------------------------------------------------------------------
def _write(tmp_path, scanner) -> dict:
    path = tmp_path / "r.json"
    cli_runner._write_report(scanner, "http://t/", str(path), "json",
                             {"target": "http://t/"})
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_scanner_reports_the_sync_engine(tmp_path):
    data = _write(tmp_path, Scanner(requester=None))
    assert data["engine"] == "sync"


def test_a_relabelled_shim_reports_the_async_engine(tmp_path):
    """`_run_async_scan` wraps async results in a sync Scanner shim.

    That shim would otherwise claim "sync" for every async run -- the same
    confusion the fallback caused, just in the opposite direction.
    """
    shim = Scanner(requester=None)
    shim.engine = "async"
    assert _write(tmp_path, shim)["engine"] == "async"


def test_fallback_reason_survives_into_the_report(tmp_path):
    scanner = Scanner(requester=None)
    scanner.engine_fallback_reason = "aiohttp is not installed"
    assert _write(tmp_path, scanner)["engine_fallback_reason"] == \
        "aiohttp is not installed"


# ---------------------------------------------------------------------------
# 5-6. The fallback itself
# ---------------------------------------------------------------------------
def test_note_async_unavailable_records_the_reason():
    args = _args()
    cli_runner._note_async_unavailable(args, "--async")
    assert "aiohttp" in args._engine_fallback_reason
    # The install hint is part of the message: "missing" without "how to fix"
    # is the kind of warning operators learn to scroll past.
    assert "xssentinel[async]" in args._engine_fallback_reason


def test_require_async_refuses_to_degrade():
    args = _args(require_async=True)
    with pytest.raises(SystemExit) as exc:
        cli_runner._note_async_unavailable(args, "--async")
    # 3 = "this run cannot support the conclusion you asked for", the same code
    # the completeness gate uses.  Not 1 (findings) and not 2 (usage).
    assert exc.value.code == 3


def test_require_async_is_a_parser_flag():
    from xssentinel.__main__ import build_parser
    args = build_parser().parse_args(["-u", "http://127.0.0.1:1/",
                                      "--require-async"])
    assert args.require_async is True


def test_require_async_defaults_off():
    from xssentinel.__main__ import build_parser
    args = build_parser().parse_args(["-u", "http://127.0.0.1:1/"])
    assert args.require_async is False


def test_help_states_the_real_flag_count():
    """The epilog quotes a flag count to orient the reader.

    It is computed at build time, not written down: a hard-coded "153 flags"
    rots the moment a flag is added, and this is the number a first-time user
    reads before deciding whether to scroll 650 lines.  Same lesson as the
    benchmark slice size (192 -> 194 went unnoticed for weeks).
    """
    from xssentinel.__main__ import build_parser
    ap = build_parser()
    n = len({a.dest for a in ap._actions if a.option_strings})
    assert f"({n} flags below" in ap.epilog, (
        f"epilog does not quote the real flag count ({n}); it says: "
        f"{ap.epilog.splitlines()[0]!r}")


# ---------------------------------------------------------------------------
# Docstring placement (the async entry point lost its own)
# ---------------------------------------------------------------------------
def test_run_async_scan_has_a_real_docstring():
    """It used to sit after the first statement, so it was a bare string
    literal: `help()` showed nothing and the function documented itself only
    to readers of the source."""
    doc = cli_runner._run_async_scan.__doc__ or ""
    assert "AsyncScanner" in doc
    assert "fall" in doc.lower()
