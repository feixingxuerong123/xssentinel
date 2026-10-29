"""The runner's skip reporting must not itself be a silent claim.

`run_all_batched.py` now prints "skipped tests: N" so that a green gate
cannot be read as "everything ran".  That number comes from
`_skip_counts()`, which parses pytest's summary line out of captured
stdout.

A reporting helper that returns 0 on input it does not understand is the
same defect this session has been chasing all round: it produces the
right-looking number for the wrong reason.  The dangerous inputs are not
the happy ones -- they are the ones that make the parser guess:

  * stdout=None, which is exactly what subprocess.TimeoutExpired hands
    back (run_all_batched.py:102), so a timed-out file would otherwise be
    silently counted as "0 skipped";
  * a truncated summary, which is what capture_output produces when a
    file dies mid-run;
  * a summary whose numbers appear in an unexpected order;
  * a file that produced no summary at all.

This asserts the contract, including the honest part: when the parser
cannot tell, it must return 0 rather than invent a number, and
`run_all_batched` must then NOT claim the gate was complete.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _runner():
    spec = importlib.util.spec_from_file_location(
        "_batched", os.path.join(ROOT, "tests", "run_all_batched.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RUNNER = _runner()


@pytest.mark.parametrize("payload,expected_skipped,expected_whole", [
    (b"3 passed in 2.1s\n", 0, False),
    (b"3 skipped in 0.07s\n", 3, True),
    (b"2 failed, 7 passed, 3 skipped in 1.2s\n", 3, False),
    (b"", 0, False),
    (None, 0, False),                     # the timeout path
    (b"garbage without any counts\n", 0, False),
])
def test_skip_counts_reads_the_summary(payload, expected_skipped,
                                       expected_whole):
    skipped, whole = RUNNER._skip_counts(payload)
    assert skipped == expected_skipped, (
        f"got skipped={skipped}, expected {expected_skipped} "
        f"for {payload!r}")
    assert whole is expected_whole, (
        f"got whole_file_skipped={whole}, expected {expected_whole} "
        f"for {payload!r}")


def test_a_whole_file_skip_is_distinguished_from_a_partial_one():
    """The distinction is the whole point: a fully-skipped file
    contributed NOTHING while still counting as green, and a partial
    skip means some coverage did happen."""
    _s, whole_file = RUNNER._skip_counts(b"3 skipped in 0.07s\n")
    _s, partial = RUNNER._skip_counts(b"7 passed, 1 skipped in 1.2s\n")
    assert whole_file is True
    assert partial is False


@pytest.mark.parametrize("rc,payload,expected", [
    # A file that really ran: pytest exits 0.
    (0, b"7 passed in 1.0s\n", "green"),
    # Module-level skip (pytest.importorskip / allow_module_level=True):
    # pytest 9 reports "1 skipped" and exits 5 -- measured 2026-10-29 on
    # 9.1.1 (local) and 9.2.0 (hosted CI).  This is green-as-skipped.
    (5, b"1 skipped in 0.01s\n", "whole-skip"),
    (5, b"1 skipped, 1 warning in 0.03s\n", "whole-skip"),
    # An EMPTY file also exits 5, but nothing declared a skip: red, because
    # "no tests here" is a defect, not a dependency gate.
    (5, b"no tests ran in 0.01s\n", "red"),
    # A real failure mentioning skips is still a failure.
    (1, b"2 failed, 3 skipped in 2.0s\n", "red"),
    (2, b"", "red"),                        # timeout path (no stdout)
    (1, None, "red"),                       # subprocess produced nothing
])
def test_file_verdict_three_way_matrix(rc, payload, expected):
    """rc==5 must not be read as 'red' OR as 'green' wholesale.

    Reading it as red made a legal dependency skip fail the hosted gate
    (2026-10-29: test_nuclei_import, PyYAML absent).  Reading it as green
    would let an empty/broken file pass unnoticed.  Only a pytest summary
    that actually says "N skipped" separates the two.
    """
    assert RUNNER._file_verdict(rc, payload) == expected


def test_module_skip_predicate_is_not_a_blanket_rc5_pass():
    """The predicate must key on the summary, not on the exit code alone."""
    assert RUNNER._module_skipped(5, b"1 skipped in 0.01s\n") is True
    assert RUNNER._module_skipped(5, b"no tests ran in 0.01s\n") is False
    assert RUNNER._module_skipped(5, b"") is False
    assert RUNNER._module_skipped(5, None) is False
    assert RUNNER._module_skipped(0, b"1 skipped in 0.01s\n") is False
    assert RUNNER._module_skipped(1, b"1 skipped in 0.01s\n") is False


def test_the_counts_survive_trailing_noise_after_the_summary():
    """The counts must come from the summary, wherever it sits.

    pytest puts the summary line LAST under `-q`, so a helper that reads
    only the final line works by ACCIDENT -- and stops working the moment
    a rerun banner, a warning block or a teardown traceback lands after
    it.  That is the real risk this guards: the count must not depend on
    being the final line.

    Mutation note: an earlier version of this test claimed to catch "a
    helper that reads the last line" and was VACUOUS.  The helper scans
    the whole buffer, so a last-line rewrite produced identical results
    and the suite stayed green (dev/_skip_reporting_mutation.py, M2 --
    went_red=False).  The input below is what actually distinguishes the
    two: the summary is followed by noise, so last-line parsing yields 0.
    """
    summary_then_noise = (
        b"....                                          [100%]\n"
        b"3 skipped, 1 rerun in 2.40s\n"
        b"WARNING  xssentinel: something happened during teardown\n")
    skipped, whole = RUNNER._skip_counts(summary_then_noise)
    assert skipped == 3, (
        f"the trailing noise hid the skip count: got {skipped}. A "
        f"last-line parser returns 0 here.")
    assert whole is True

    # The control: the same shape WITHOUT the skip must still report 0,
    # so this test cannot pass by always returning 3.
    passed_then_noise = (
        b"....                                          [100%]\n"
        b"4 passed, 1 rerun in 2.40s\n"
        b"WARNING  xssentinel: something happened during teardown\n")
    assert RUNNER._skip_counts(passed_then_noise) == (0, False)
