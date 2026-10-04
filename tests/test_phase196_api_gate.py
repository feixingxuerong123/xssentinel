# -*- coding: utf-8 -*-
"""Phase 196: the same-origin gate must guard BOTH HTTP front-ends.

Why this is a real hole and not a tidiness pass: Phase 70 put the
DNS-rebinding / cross-site defence inside ``StdlibServer``, and ``FlaskServer``
(which ``--use-flask`` mounts, and which is the documented way to embed the
API in an existing service) never called it.  With no ``--api-key`` -- the
default, warned about since Phase 190 but still allowed -- a rebound page
could GET ``/api/v1/scans/<id>/findings`` and read the results, and a
cross-site form POST could start scans.  Nothing in the test suite covered
the Flask path at all, so the asymmetry survived eight phases of API tests.

Absorbed from the same place dalfox fixed it (#1356: "server refuses
browser-driven cross-site and DNS-rebound requests via an Origin /
Sec-Fetch-Site / Host gate").  ``Sec-Fetch-Site`` is the part the Host and
Origin strings cannot cover: a rebound page looks same-origin to both, and
only the browser says which site it came from.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.api.server import (  # noqa: E402
    FlaskServer, StdlibServer, base_local_hosts, host_name_of, same_origin_ok)

LOCAL = base_local_hosts("127.0.0.1")


# ---------------------------------------------------------------------------
# the shared predicate, spelled once
# ---------------------------------------------------------------------------
def test_host_name_strips_port_keeps_ipv6():
    assert host_name_of("127.0.0.1:8000") == "127.0.0.1"
    assert host_name_of("[::1]:8000") == "::1"
    assert host_name_of("evil.example") == "evil.example"


def test_rebound_host_is_rejected_when_no_secret_is_configured():
    ok, reason = same_origin_ok("GET", {"Host": "evil.example"}, LOCAL, False)
    assert ok is False and "not a local host" in reason


def test_api_key_delegates_the_host_question_to_the_secret():
    # Phase 190: `--host 0.0.0.0 --api-key X` must serve remote callers that
    # name the host they actually reached.
    ok, _ = same_origin_ok("GET", {"Host": "192.168.1.5:8000"}, LOCAL, True)
    assert ok is True
    ok2, _ = same_origin_ok("GET", {"Host": "192.168.1.5:8000"}, LOCAL, False)
    assert ok2 is False


def test_cross_site_sec_fetch_site_is_rejected_for_every_method():
    for method in ("GET", "POST", "DELETE"):
        ok, reason = same_origin_ok(method, {
            "Host": "127.0.0.1:8000",
            "Sec-Fetch-Site": "cross-site"}, LOCAL, True)
        assert ok is False, (method, reason)
    # same-origin / same-site / none (typed URL, bookmark) still pass
    for sfs in ("same-origin", "same-site", "none", ""):
        ok, _ = same_origin_ok("POST", {"Host": "127.0.0.1:8000",
                                        "Sec-Fetch-Site": sfs}, LOCAL, True)
        assert ok is True, sfs


def test_foreign_origin_state_change_is_rejected():
    ok, reason = same_origin_ok("POST", {
        "Host": "127.0.0.1:8000",
        "Origin": "http://evil.example"}, LOCAL, True)
    assert ok is False and "cross-origin state change" in reason
    # a GET carries no Origin from a normal navigation, so reads stay open
    ok2, _ = same_origin_ok("GET", {"Host": "127.0.0.1:8000"}, LOCAL, False)
    assert ok2 is True


# ---------------------------------------------------------------------------
# the stdlib front-end keeps behaving exactly as before (regression pin)
# ---------------------------------------------------------------------------
def test_stdlib_server_still_enforces_the_gate():
    srv = StdlibServer(host="127.0.0.1", port=0)
    assert srv._same_origin_ok("GET", {"Host": "evil.example"})[0] is False
    assert srv._same_origin_ok("GET", {"Host": "localhost:8000"})[0] is True


# ---------------------------------------------------------------------------
# and Flask now enforces it too -- this is the part that was missing
# ---------------------------------------------------------------------------
@pytest.fixture()
def flask_client():
    """Drive the real WSGI app.

    ``app.test_client()`` is NOT usable in this environment: Flask 2.2.5's
    EnvironBuilder reads ``werkzeug.__version__``, which the installed
    Werkzeug no longer exposes, so it raises before the request is built --
    a broken helper, not a broken app.  werkzeug.test.Client goes through the
    same WSGI callable, so the gate under test is the one that ships.
    """
    pytest.importorskip("werkzeug")
    from werkzeug.test import Client
    srv = FlaskServer()
    return Client(srv.app)


def _get(client, **headers):
    return client.get("/api/v1/scans", headers=headers)


def _post(client, **headers):
    return client.post("/api/v1/scans", json={"url": "http://127.0.0.1/x"},
                       headers=headers)


def test_flask_rejects_a_rebound_host(flask_client):
    r = _get(flask_client, Host="evil.example")
    assert r.status_code == 403, r.status_code
    assert r.get_json()["error"] == "cross_origin_blocked"


def test_flask_rejects_a_cross_site_browser_post(flask_client):
    r = _post(flask_client, Host="127.0.0.1:8000",
              **{"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403, r.get_json()


def test_flask_rejects_a_foreign_origin_post(flask_client):
    r = _post(flask_client, Host="127.0.0.1:8000",
              Origin="http://evil.example")
    assert r.status_code == 403, r.get_json()


def test_flask_preflight_is_not_gated_but_the_real_request_is(flask_client):
    """A preflight is not a state change and carries no data.

    Gating it answered 403 to the OPTIONS of exactly the origins
    ``--cors-origins`` exists to allow (measured before the exemption), which
    stopped those callers from ever reaching the request the gate does police
    -- and the stdlib front-end never gated it either, since do_OPTIONS is a
    separate method.  The follow-up POST must still be refused.
    """
    hdrs = {"Origin": "https://partner.example",
            "Sec-Fetch-Site": "cross-site", "Host": "127.0.0.1:8000"}
    preflight = flask_client.open("/api/v1/scans", method="OPTIONS",
                                  headers=hdrs)
    assert not str(preflight.status).startswith("403"), preflight.status
    real = flask_client.post("/api/v1/scans", json={}, headers=hdrs)
    assert str(real.status).startswith("403"), real.status


def test_flask_still_serves_local_and_non_browser_clients(flask_client):
    # reverse control: the gate must not turn into a blanket denial --
    # curl/SDK send none of these browser headers and must pass untouched
    assert _get(flask_client, Host="127.0.0.1:8000").status_code == 200
    assert _get(flask_client).status_code == 200


def test_both_front_ends_agree_case_by_case(flask_client):
    """The whole point of one shared predicate: the two servers cannot drift."""
    std = StdlibServer(host="127.0.0.1", port=0)
    cases = [
        ("GET", {"Host": "evil.example"}),
        ("GET", {"Host": "127.0.0.1:8000", "Sec-Fetch-Site": "cross-site"}),
        ("POST", {"Host": "127.0.0.1:8000", "Origin": "http://evil.example"}),
        ("GET", {"Host": "127.0.0.1:8000"}),
        ("POST", {"Host": "localhost"}),
    ]
    for method, headers in cases:
        expected = std._same_origin_ok(method, headers)[0]
        client = flask_client
        resp = (client.get("/api/v1/scans", headers=headers)
                if method == "GET" else
                client.post("/api/v1/scans", json={}, headers=headers))
        # werkzeug.test.Client reports the status as a string ("403 FORBIDDEN")
        allowed = not str(resp.status).startswith("403")
        assert allowed is expected, (method, headers, resp.status)
