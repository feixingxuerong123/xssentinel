"""Range7 construction validity: the -safe twins must be safe BY THE BYTES.

A range is only evidence if its halves are what they claim.  Range4's
first draft taught this the hard way: the "safe" twin also reflected the
parameter into a server-side script line, so the case was vulnerable and
the scanner's correct finding was scored as a false positive.

So before any scanner runs, this asserts on the SERVED BYTES:

  * every vulnerable route returns the marker raw (the injection point is
    real, not a coincidence of the scanner's payload);
  * no -safe route ever returns the marker raw -- escaping or \\x3c
    encoding must be visible in the response;
  * the two profile pages differ exactly in innerHTML vs textContent;
  * the stored pair really stores and renders (POST then GET), so a
    TN on the safe thread cannot come from an empty page.
"""
from __future__ import annotations

import http.client
import importlib.util
import socket
import threading
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "range7_server", ROOT / "range7" / "server.py")
srv_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv_mod)

MARK = "<svg onload=alert(1)>"


@pytest.fixture(scope="module")
def base():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    started = threading.Event()
    threading.Thread(target=srv_mod.run_server, args=(port,),
                     kwargs={"ready_callback": lambda _s: started.set()},
                     daemon=True).start()
    assert started.wait(10), "range7 server did not start"
    return f"http://127.0.0.1:{port}"


def _get(base: str, path: str) -> tuple[int, str]:
    u = urllib.parse.urlsplit(base + path)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    conn.request("GET", u.path + (("?" + u.query) if u.query else ""))
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def _post(base: str, path: str, text: str) -> None:
    u = urllib.parse.urlsplit(base + path)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    body = urllib.parse.urlencode({"text": text})
    conn.request("POST", u.path, body=body,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    conn.getresponse().read()
    conn.close()


def test_attribute_face(base):
    q = urllib.parse.quote(MARK)
    _, raw = _get(base, f"/search?q={q}")
    assert MARK in raw, "vulnerable attribute face must carry the bytes raw"
    _, safe = _get(base, f"/search-safe?q={q}")
    assert MARK not in safe, "safe attribute face returned the payload raw"
    assert "&lt;svg" in safe


def test_script_string_face(base):
    payload = "</script><svg onload=alert(1)>"
    q = urllib.parse.quote(payload)
    _, raw = _get(base, f"/widget?cfg={q}")
    assert payload in raw, "vulnerable script face must allow the breakout"
    _, safe = _get(base, f"/widget-safe?cfg={q}")
    assert payload not in safe
    assert "\\x3c/script" in safe, "safe face must encode '<' for JS"


def test_stored_face(base):
    _post(base, "/comment", MARK)
    _post(base, "/comment-safe", MARK)
    _, raw = _get(base, "/thread")
    assert MARK in raw, "raw thread must render the stored bytes"
    _, safe = _get(base, "/thread-safe")
    assert MARK not in safe
    assert "&lt;svg" in safe
    # the page must actually have content -- a TN on an empty page is fiction
    assert "cm" in safe


def test_dom_faces_differ_only_in_the_sink(base):
    _, raw = _get(base, "/profile")
    _, safe = _get(base, "/profile-safe")
    assert "innerHTML" in raw and "textContent" not in raw
    assert "textContent" in safe and "innerHTML" not in safe
    # both must decode the fragment -- Phase 265: Chromium percent-encodes
    assert "decodeURIComponent" in raw and "decodeURIComponent" in safe


def test_json_config_block_face(base):
    payload = "</script><svg onload=alert(1)>"
    q = urllib.parse.quote(payload)
    _, raw = _get(base, f"/preview?name={q}")
    assert payload in raw, "vulnerable JSON block must allow closing the element"
    _, safe = _get(base, f"/preview-safe?name={q}")
    assert payload not in safe
    assert "\\u003c/script" in safe, "safe twin must JSON-escape '<'"


def test_second_order_face(base):
    _post(base, "/settings", MARK)
    _post(base, "/settings-safe", MARK)
    _, raw = _get(base, "/admin")
    assert MARK in raw, "second-order view must render the stored bytes"
    _, safe = _get(base, "/admin-safe")
    assert MARK not in safe
    assert "&lt;svg" in safe
    assert "nm" in safe, "an empty admin page would make the TN fiction"
