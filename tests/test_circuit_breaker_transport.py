# -*- coding: utf-8 -*-
"""Phase 208: the circuit breaker can see a target that says nothing.

``CircuitBreaker.record`` takes an HTTP status, so every failure mode that
never produces one was invisible to it: connection refused, filtered IP,
DNS black hole.  The streak stayed at zero, the breaker never tripped,
and the scan kept re-issuing a request the target had already refused --
measured on a closed port here at >180s for a scan in which every request
failed, which is also how a range3 case outlived its own runner timeout.

Two streaks, because the two justify different stopping points:

    a 5xx     one endpoint misbehaving; the others may still work
    silence   the target as a whole is not answering

so silence trips at its own, lower threshold, and any response clears both
(a target that recovers mid-scan must not stay open).

These tests drive the breaker and the Requester directly against a closed
port -- no fixture server, and nothing that can pass by being slow.

Run:  pytest tests/test_circuit_breaker_transport.py
"""
from __future__ import annotations

import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.budget import CircuitBreaker  # noqa: E402
from xssentinel.core.requester import Requester  # noqa: E402


def _closed_port() -> int:
    """A port nothing is listening on: bind, read the number, release."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestTransportFailuresCount:
    """Refusals enter a streak of their own."""

    def test_refusals_accumulate_and_trip(self):
        cb = CircuitBreaker(threshold=25, window=120.0)
        # The default transport threshold is deliberately well below 25.
        for _ in range(cb.transport_threshold):
            assert not cb.tripped, "tripped before reaching its own threshold"
            cb.record_transport_failure()
        assert cb.tripped

    def test_one_refusal_is_not_enough(self):
        """A single dropped connection is noise, not an outage."""
        cb = CircuitBreaker(threshold=25, window=120.0)
        cb.record_transport_failure()
        assert not cb.tripped

    def test_silence_trips_sooner_than_a_five_hundred(self):
        """The whole point of the separate threshold.

        25 x 5xx is a bad endpoint and worth grinding through; 5 refusals
        means nothing else is reachable either.
        """
        cb = CircuitBreaker(threshold=25, window=120.0)
        assert cb.transport_threshold < cb.threshold, (
            "silence must justify stopping before a 5xx run does")

    def test_a_response_clears_the_transport_streak(self):
        """Recovery must re-open the scan.

        A target that answers again has disproven its own outage; leaving
        the breaker tripped would strand the rest of the run.
        """
        cb = CircuitBreaker(threshold=25, window=120.0)
        for _ in range(cb.transport_threshold - 1):
            cb.record_transport_failure()
        assert not cb.tripped
        cb.record(200)
        for _ in range(cb.transport_threshold - 1):
            cb.record_transport_failure()
        assert not cb.tripped, "stale refusals from before a 200 counted"

    def test_the_two_streaks_are_tracked_apart(self):
        """A 5xx run and a refusal run are not interchangeable evidence."""
        cb = CircuitBreaker(threshold=3, transport_threshold=3, window=120.0)
        cb.record(500)
        cb.record(500)
        cb.record_transport_failure()
        # 2 statuses + 1 silence, under both thresholds.
        assert not cb.tripped
        assert cb.failure_streak == 3

    def test_describe_says_which_evidence_tripped_it(self):
        """The message must not send the reader to the wrong problem."""
        cb = CircuitBreaker(threshold=25, transport_threshold=2, window=120.0)
        cb.record_transport_failure()
        cb.record_transport_failure()
        assert "no response" in cb.describe()
        cb2 = CircuitBreaker(threshold=1, window=120.0)
        cb2.record(503)
        assert "5xx/429" in cb2.describe()


class TestRequesterFeedsTheBreaker:
    """The wiring: a raised request has to reach the breaker at all.

    The unit tests above prove the breaker counts; these prove anything
    that asks a Requester to hit a closed port is counted, which is the
    only way the breaker learns about an outage at all.
    """

    def test_refused_requests_trip_a_requesters_breaker(self):
        req = Requester(timeout=3,
                        breaker=CircuitBreaker(threshold=25, window=120.0))
        url = f"http://127.0.0.1:{_closed_port()}/x"
        for _ in range(req.breaker.transport_threshold):
            with pytest.raises(Exception):
                req.get(url)
        assert req.breaker.tripped

    def test_the_next_request_is_refused_before_being_sent(self):
        """Tripped must be load-bearing: no eleventh probe to a dead host."""
        req = Requester(timeout=3,
                        breaker=CircuitBreaker(threshold=25, window=120.0))
        url = f"http://127.0.0.1:{_closed_port()}/x"
        for _ in range(req.breaker.transport_threshold):
            with pytest.raises(Exception):
                req.get(url)
        # This call must not touch the network at all.
        with pytest.raises(Exception) as exc:
            req.get(url)
        assert "circuit open" in str(exc.value).lower()

    def test_failures_are_counted_in_the_tally_too(self):
        """The report reads the tally, not the breaker, for 'did it reach'."""
        req = Requester(timeout=3,
                        breaker=CircuitBreaker(threshold=25, window=120.0))
        url = f"http://127.0.0.1:{_closed_port()}/x"
        with pytest.raises(Exception):
            req.get(url)
        assert req.attempted_requests == 1
        assert req.failed_requests == 1