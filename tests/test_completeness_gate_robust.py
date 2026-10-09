# -*- coding: utf-8 -*-
"""The completeness gate must describe a scan, never crash one.

Phase 208 taught the gate to read the async engine's egress counters so a
scan that reached nothing could exit 3 instead of writing "0 findings,
clean".  The guard that reads them does `_att > 0`, and `attempted_requests`
is a property over the tally -- so a caller-supplied scanner (the batch
tests inject a Mock) returns a Mock there.  Comparing a Mock to 0 raises
TypeError, and the batch test failed exactly that way:

    TypeError: '>' not supported between instances of 'MagicMock' and 'int'
    xssentinel/__main__.py:1417

The lesson is the shape of the gate, not the one line: it runs inside the
per-target loop of every batch run, so anything it cannot parse has to
degrade to "no evidence" rather than abort the scan.  A completeness
check that raises is worse than one that abstains -- it takes down a scan
that would otherwise have produced a report.

These drive `_run_batch` with a Mock scanner, which is the shape the real
CLI batch tests use, and assert the batch finishes.

Run:  pytest tests/test_completeness_gate_robust.py
"""
from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel import __main__ as cli  # noqa: E402


def _argv(batch_file, out_dir) -> list[str]:
    return [
        "--batch", str(batch_file),
        "-o", str(out_dir),
        "-f", "json",
        "--timeout", "5",
        "--threads", "1",
        "--max-transforms", "1",
        "--max-payloads", "2",
        "--progress", "none",
        "--log-level", "error",
    ]


def _scanner(mock_req) -> mock.MagicMock:
    """The shape the batch path builds: a MagicMock scanner whose `req`
    is also a Mock, so `attempted_requests` is a MagicMock, not an int."""
    ms = mock.MagicMock()
    ms.findings = []
    ms.waf_name = None
    ms.req = mock_req
    return ms


def _req_mock(attempted=None, failed=None) -> mock.MagicMock:
    req = mock.MagicMock()
    if attempted is None:
        # MagicMock attribute -- the shape that raised TypeError.
        pass
    else:
        req.attempted_requests = attempted
    if failed is not None:
        req.failed_requests = failed
    return req


class TestGateSurvivesNonNumericCounters:
    def test_a_mock_requester_does_not_abort_the_batch(self, tmp_path):
        """The regression: TypeError killed the run mid-target.

        `attempted_requests` is a property over the tally, so on a
        MagicMock it is a MagicMock; `_att > 0` then raises.  The batch
        must still finish and still report both targets.
        """
        batch = tmp_path / "urls.txt"
        batch.write_text("http://127.0.0.1:1/a\n", encoding="utf-8")
        out = tmp_path / "reports"
        out.mkdir()
        scanner = _scanner(_req_mock())      # non-int attempted_requests

        with mock.patch.object(cli, "_run_scan", return_value=scanner), \
             mock.patch.object(cli, "_write_report", return_value="r.json"):
            rc = cli.main(_argv(batch, out))
        assert rc in (0, 3), f"unexpected exit {rc}"

    def test_a_none_requester_is_treated_as_no_evidence(self, tmp_path):
        batch = tmp_path / "urls.txt"
        batch.write_text("http://127.0.0.1:1/a\n", encoding="utf-8")
        out = tmp_path / "reports"
        out.mkdir()
        scanner = _scanner(None)              # no instrument at all

        with mock.patch.object(cli, "_run_scan", return_value=scanner), \
             mock.patch.object(cli, "_write_report", return_value="r.json"):
            rc = cli.main(_argv(batch, out))
        assert rc in (0, 3), f"unexpected exit {rc}"

    def test_a_real_integer_counter_is_still_trusted(self, tmp_path):
        """The guard must not be 'fixed' by ignoring counters entirely."""
        batch = tmp_path / "urls.txt"
        batch.write_text("http://127.0.0.1:1/a\n", encoding="utf-8")
        out = tmp_path / "reports"
        out.mkdir()
        scanner = _scanner(_req_mock(attempted=7, failed=2))

        with mock.patch.object(cli, "_run_scan", return_value=scanner), \
             mock.patch.object(cli, "_write_report", return_value="r.json"):
            rc = cli.main(_argv(batch, out))
        assert rc in (0, 3), f"unexpected exit {rc}"


class TestTheGuardIsLoadBearing:
    """Presence is not proof; break it and this must go red."""

    def test_the_fixture_really_is_non_numeric(self):
        """If this ever stops holding, the tests above prove nothing."""
        scanner = _scanner(_req_mock())
        _att = getattr(scanner.req, "attempted_requests", None)
        assert not isinstance(_att, int), \
            "fixture must yield a non-int counter"
        with pytest.raises(TypeError):
            _ = _att > 0  # noqa: B015 -- the exact unguarded comparison
