# -*- coding: utf-8 -*-
"""Phase 347: a failed request must say WHY, not only how many failed.

Why this file exists
--------------------
Measured on a closed port with ``--log-level debug``: five requests were
attempted, five got no response, and the only output was

    [!] Scan incomplete: 5 of 5 request(s) received no response ...

The count was right and the diagnosis was absent.  A dead host, a proxy that
swallowed the traffic and a TLS handshake that never finished all produce that
identical line, so the operator's next move (retry? check the host? unset
HTTP_PROXY?) is a guess.  The async engine already logged its baseline
exception; the sync path recorded the number and dropped the cause.

What this locks
---------------
1. ``describe_transport_failure`` groups by exception class and keeps the
   message as an example -- low-cardinality key, human-readable value.
2. ``_Tally`` counts and remembers, and the first example wins (later ones for
   the same class are usually the same text with a different port).
3. A real refused connection surfaces a named reason through the public
   ``Requester.failure_reasons`` property -- the probe goes through the real
   ``_send`` path, not a stand-in that fakes the exception.
4. The CLI helper prints the cause next to the verdict, and the JSON report
   carries the same field.
"""
import json
import socket
import sys

import pytest

sys.path.insert(0, ".")

from xssentinel.core.requester import (Requester, _Tally,
                                       describe_transport_failure)
from xssentinel.core.report import build_json

from tests.conftest import loopback_healthy  # noqa: E402  (root on sys.path)


# -- 1. label/detail split -------------------------------------------------

def test_describe_splits_class_from_message():
    exc = ConnectionError("Connection refused: http://h:1/?q=1")
    label, detail = describe_transport_failure(exc)
    assert label == "ConnectionError"
    assert detail == "Connection refused: http://h:1/?q=1"


def test_describe_collapses_whitespace_and_truncates():
    exc = TimeoutError("read\n  timed  out\t" + "x" * 400)
    label, detail = describe_transport_failure(exc, limit=40)
    assert label == "TimeoutError"
    assert "\n" not in detail and "\t" not in detail
    assert len(detail) <= 40, "the limit is a ceiling, not a suggestion"
    assert detail.endswith("\u2026"), "a cut message must say it was cut"


def test_describe_leaves_short_messages_alone():
    _, detail = describe_transport_failure(ConnectionError("refused"), limit=40)
    assert detail == "refused", "no ellipsis on a message that fits"


def test_label_is_the_class_not_the_message():
    """Two different hosts must group under one key.

    This is the property that keeps a 500-target batch from producing 500
    distinct "reasons" -- the reason is the failure MODE.
    """
    a, _ = describe_transport_failure(ConnectionError("host a refused"))
    b, _ = describe_transport_failure(ConnectionError("host b refused"))
    assert a == b == "ConnectionError"


# -- 2. tally semantics ----------------------------------------------------

def test_tally_counts_and_keeps_first_example():
    tally = _Tally()
    tally.note_failure(ConnectionError("first"))
    tally.note_failure(ConnectionError("second"))
    tally.note_failure(TimeoutError("slow"))

    assert tally.failed == 3
    assert tally.failure_reasons["ConnectionError"] == 2
    assert tally.failure_examples["ConnectionError"] == "first"
    assert tally.failure_examples["TimeoutError"] == "slow"


def test_top_reasons_is_ordered_and_limited():
    tally = _Tally()
    for _ in range(3):
        tally.note_failure(ConnectionError("refused"))
    for _ in range(2):
        tally.note_failure(TimeoutError("slow"))
    tally.note_failure(ValueError("odd"))

    top = tally.top_failure_reasons(limit=2)
    assert [r["reason"] for r in top] == ["ConnectionError", "TimeoutError"]
    assert [r["count"] for r in top] == [3, 2]
    assert top[0]["example"] == "refused"


def test_empty_tally_reports_nothing():
    """No failures must not invent a reason -- an empty list, not a placeholder."""
    assert _Tally().top_failure_reasons() == []


def test_direct_failed_assignment_does_not_desync():
    """cli_runner copies the async count by assigning `.failed` directly.

    That path measures its own failures, so it legitimately has no reasons.
    The property must stay empty rather than fabricate one from the count.
    """
    tally = _Tally()
    tally.failed = 7
    assert tally.failure_reasons == {}
    assert tally.top_failure_reasons() == []


# -- 3. the real path ------------------------------------------------------

def _closed_port() -> int:
    """A port nothing listens on: bind, learn the number, release it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_transport_exception_is_named_without_network():
    """The wiring, verified deterministically.

    ``session.request`` is the transport boundary -- the same seam the real
    socket sits behind.  Replacing it keeps ``_send``, the failover branch,
    the tally and the public property all real, so this test still fails if
    the recording is removed from ``_send``; it only removes the dependency
    on a throttled loopback.  The loopback test below is the end-to-end one.
    """
    import requests

    req = Requester(timeout=3, max_retries=0)

    def _boom(*a, **kw):
        raise requests.exceptions.ConnectionError(
            "[WinError 10061] No connection could be made")

    req.session.request = _boom
    with pytest.raises(Exception):
        req.get("http://127.0.0.1:1/?q=1")

    assert req.failed_requests == 1
    assert req.failure_reasons == [{
        "reason": "ConnectionError",
        "count": 1,
        "example": "[WinError 10061] No connection could be made",
    }]


def test_real_refused_connection_is_named():
    """End-to-end through Requester.get -> _send -> tally.

    Gated on loopback health (this host throttles connects under AV load);
    a skip here is honest -- it means the probe never ran, not that it passed.
    """
    if not loopback_healthy():
        pytest.skip("loopback throttled: refused-connection probe not runnable")

    req = Requester(timeout=3, max_retries=0)
    req.session.trust_env = False          # ignore HTTP_PROXY for the probe
    port = _closed_port()
    with pytest.raises(Exception):
        req.get(f"http://127.0.0.1:{port}/?q=1")

    assert req.failed_requests >= 1
    reasons = req.failure_reasons
    assert reasons, "a failed request must carry a reason"
    assert reasons[0]["reason"], "the reason must name the failure mode"
    assert reasons[0]["count"] >= 1


def test_clone_shares_the_reason_tally():
    req = Requester(timeout=3, max_retries=0)
    req.tally.note_failure(ConnectionError("via clone"))
    assert req.clone().failure_reasons[0]["reason"] == "ConnectionError"


# -- 4. operator-facing surfaces ------------------------------------------

def test_cli_helper_prints_the_cause(capsys):
    from xssentinel.__main__ import _print_failure_reasons
    _print_failure_reasons({
        "ConnectionError": {"count": 5, "example": "refused"},
        "TimeoutError": {"count": 1, "example": "slow"},
    })
    err = capsys.readouterr().err
    assert "ConnectionError x5" in err
    assert "refused" in err
    assert "TimeoutError x1" in err


def test_cli_helper_silent_without_reasons(capsys):
    from xssentinel.__main__ import _print_failure_reasons
    _print_failure_reasons({})
    assert capsys.readouterr().err == ""


def test_json_report_carries_the_reasons():
    meta = {"requests_attempted": 5, "requests_failed": 5,
            "request_failure_reasons": [
                {"reason": "ConnectionError", "count": 5,
                 "example": "refused"}]}
    out = json.loads(build_json([], "http://h/", meta))
    assert out["request_failure_reasons"] == [
        {"reason": "ConnectionError", "count": 5, "example": "refused"}]


def test_json_report_defaults_to_empty_list():
    """An older caller that never fills the field must not emit null.

    A consumer that iterates the field would crash on None; the field is
    documented as a list, so the default has to be one.
    """
    out = json.loads(build_json([], "http://h/", {}))
    assert out["request_failure_reasons"] == []


# -- 5. environment proxy visibility --------------------------------------

def test_env_proxy_reported_when_set(monkeypatch):
    from xssentinel.core.requester import env_proxy_for
    monkeypatch.setattr("requests.utils.getproxies",
                        lambda: {"http": "http://127.0.0.1:33312"})
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert env_proxy_for("http://127.0.0.1:8080/") == "http://127.0.0.1:33312"


def test_env_proxy_absent_when_environment_has_none(monkeypatch):
    from xssentinel.core.requester import env_proxy_for
    monkeypatch.setattr("requests.utils.getproxies", lambda: {})
    assert env_proxy_for("http://127.0.0.1:8080/") is None


def test_no_proxy_bypass_is_honoured(monkeypatch):
    """The claim is "a proxy is in effect", so NO_PROXY must silence it.

    This goes through requests' own bypass resolver rather than a private
    re-implementation -- the warning may only describe traffic that really
    goes to the proxy.
    """
    from xssentinel.core.requester import env_proxy_for
    monkeypatch.setattr("requests.utils.getproxies",
                        lambda: {"http": "http://127.0.0.1:33312"})
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    assert env_proxy_for("http://127.0.0.1:8080/") is None


def test_cli_notes_the_proxy(monkeypatch, capsys):
    import xssentinel.__main__ as cli
    monkeypatch.setattr(cli, "env_proxy_for", lambda url: "http://p:1")
    cli._note_env_proxy(["http://127.0.0.1:8080/"], _Args())
    err = capsys.readouterr().err
    assert "Environment proxy in effect" in err
    assert "http://p:1" in err
    assert "NO_PROXY" in err, "the note must say how to opt out"


def test_cli_silent_when_operator_named_a_proxy(monkeypatch, capsys):
    """An explicit -x is not news; only the implicit egress is."""
    import xssentinel.__main__ as cli
    monkeypatch.setattr(cli, "env_proxy_for", lambda url: "http://p:1")
    cli._note_env_proxy(["http://127.0.0.1:8080/"],
                        _Args(proxy="http://explicit:8080"))
    assert capsys.readouterr().err == ""


def test_cli_silent_without_proxy(monkeypatch, capsys):
    import xssentinel.__main__ as cli
    monkeypatch.setattr(cli, "env_proxy_for", lambda url: None)
    cli._note_env_proxy(["http://h/"], _Args())
    assert capsys.readouterr().err == ""


class _Args:
    """Minimal stand-in for the parsed namespace these helpers read."""

    def __init__(self, proxy=None, proxy_list=None):
        self.proxy = proxy
        self.proxy_list = proxy_list

