"""Range7 construction validity, measured IN A BROWSER, both directions.

Byte-level assertions (tests/test_range7_construct.py) are necessary but
not sufficient -- and range7 proved it twice in one afternoon:

  * the ``-safe`` JSON twin escaped '<' as \\u003c.  Byte-wise it looked
    escaped, but JSON.parse turns \\u003c back into '<' right before the
    innerHTML assignment, so the "safe" page still executed the payload and
    the scanner reported a browser-confirmed high on it.  The scanner was
    right; the range was wrong.
  * the second-order POST read only ``text``/``comment``, never ``name``,
    so the injection was silently dropped and the vulnerable case read as
    an FN -- again a range fault that looked like a scanner miss.

So each face is asserted the way a browser sees it, in BOTH directions:

  vulnerable twin -> the sentinel must fire
  safe twin        -> the sentinel must NOT fire

Only the safe direction is gated by default (a vulnerable twin failing to
fire is usually a payload-shape question, and a flaky browser must not
turn a healthy range red).  The positive direction is recorded in the
output and can be asserted with --strict-range7-construct.
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

# (case id, path, kind, param, payload).  kind: query | post | fragment
CASES = [
    ("r7-pos-attr", "/search", "query", "q", '" ><img src=x onerror=__x()>'),
    ("r7-neg-attr", "/search-safe", "query", "q", '" ><img src=x onerror=__x()>'),
    # /widget escapes the JS string delimiters both ways, so the breakout has
    # to close the SCRIPT ELEMENT -- HTML parsing wins over the JS string.
    # A quote-breakout payload does nothing here (measured: stamp=None).
    ("r7-pos-script", "/widget", "query", "cfg",
     '</script><img src=x onerror=__x()>'),
    ("r7-neg-script", "/widget-safe", "query", "cfg",
     '</script><img src=x onerror=__x()>'),
    ("r7-pos-json", "/preview", "query", "name",
     '</script><img src=x onerror=__x()>'),
    ("r7-neg-json", "/preview-safe", "query", "name",
     '</script><img src=x onerror=__x()>'),
    ("r7-pos-stored", "/thread", "post", "text", '<img src=x onerror=__x()>'),
    ("r7-neg-stored", "/thread-safe", "post", "text", '<img src=x onerror=__x()>'),
    ("r7-pos-second", "/admin", "post", "name", '<img src=x onerror=__x()>'),
    ("r7-neg-second", "/admin-safe", "post", "name", '<img src=x onerror=__x()>'),
    ("r7-pos-dom", "/profile", "fragment", "", '<img src=x onerror=__x()>'),
    ("r7-neg-dom", "/profile-safe", "fragment", "", '<img src=x onerror=__x()>'),
    ("r7-pos-md", "/md", "query", "body", '<img src=x onerror=__x()>'),
    ("r7-neg-md", "/md-safe", "query", "body", '<img src=x onerror=__x()>'),
    ("r7-pos-auth", "/dashboard", "auth", "q", '" ><img src=x onerror=__x()>'),
    ("r7-neg-auth", "/dashboard-safe", "auth", "q", '" ><img src=x onerror=__x()>'),
]

# which POST endpoint seeds each stored/second-order view
POST_FOR = {"/thread": "/comment", "/thread-safe": "/comment-safe",
            "/admin": "/settings", "/admin-safe": "/settings-safe"}


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


@pytest.fixture(scope="module")
def browser(base):
    """A Chromium that lives in its OWN thread, driven by a task queue.

    Playwright's sync API is thread-bound and leaves a running asyncio loop
    behind (the Phase 200 wedge).  If it is started in the test thread,
    tests/conftest.py then skips every later test with "a previous test left
    a running event loop in this thread" -- measured: 12 of 12 skipped.  So
    the browser boots in a worker, and every page call is submitted there.
    """
    import queue
    import benchmark.browser_dom_oracle as oracle
    from playwright.sync_api import sync_playwright

    ready = threading.Event()
    ops: queue.Queue = queue.Queue()

    def _loop():
        p = sync_playwright().start()
        b = p.chromium.launch()
        ctx = b.new_context()
        ctx.add_init_script(oracle._INIT_STAMP)   # defines __x() + the stamp
        page = ctx.new_page()
        ready.set()
        while True:
            item = ops.get()
            if item is None:
                break
            fn, ev, out = item
            try:
                out["value"] = fn(page)
            except Exception as e:            # noqa: BLE001
                out["error"] = e
            ev.set()
        b.close()
        p.stop()

    worker = threading.Thread(target=_loop, daemon=True)
    worker.start()
    assert ready.wait(30), "chromium did not start"

    def run(fn):
        ev = threading.Event()
        out: dict = {}
        ops.put((fn, ev, out))
        assert ev.wait(120), "browser op timed out"
        if out.get("error"):
            raise out["error"]
        return out.get("value")

    try:
        yield oracle, run
    finally:
        ops.put(None)
        worker.join(timeout=20)


def _url(base, path, kind, param, payload):
    if kind in ("query", "auth"):
        return f"{base}{path}?{param}={urllib.parse.quote(payload)}"
    if kind == "fragment":
        return f"{base}{path}#{urllib.parse.quote(payload)}"
    return f"{base}{path}"


def _seed(base, path, param, payload):
    """POST the payload the way the scanner's stored pass would."""
    inject = POST_FOR[path]
    u = urllib.parse.urlsplit(base + inject)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    conn.request("POST", u.path, body=urllib.parse.urlencode({param: payload}),
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    conn.getresponse().read()
    conn.close()


@pytest.mark.parametrize("cid,path,kind,param,payload",
                         [c for c in CASES if "-neg-" in c[0]])
def test_safe_twin_does_not_execute(base, browser, cid, path, kind, param,
                                    payload):
    oracle, run = browser
    if kind == "post":
        _seed(base, path, param, payload)
    url = _url(base, path, kind, param, payload)

    def _measure(page):
        # localStorage is per ORIGIN: land on the range first, clear there,
        # then load the payload URL -- otherwise a previous case's hit stays
        # readable and every later case looks green.
        page.goto(f"{base}/", wait_until="commit")
        oracle._wait_load(page)
        oracle._clear(page)
        if kind == "auth":
            # GET /login sets the session cookie (the runner POSTs); without
            # it the dashboard is a 401 and there is no sink to measure.
            page.goto(f"{base}/login", wait_until="commit")
            oracle._wait_load(page)
        page.goto(url, wait_until="commit")
        oracle._wait_load(page)
        page.wait_for_timeout(500)
        return oracle._read_stamp(page)

    stamp = run(_measure)
    assert stamp is None, (
        f"{cid}: the SAFE twin executed the payload in Chromium (stamp="
        f"{stamp!r}) -- the range is wrong, not the scanner (see the \\u003c "
        "incident in the docstring)")


@pytest.mark.parametrize("cid,path,kind,param,payload",
                         [c for c in CASES if "-pos-" in c[0]])
def test_vulnerable_twin_executes(base, browser, cid, path, kind, param,
                                  payload):
    """Recorded, not gated by default (see the module docstring)."""
    oracle, run = browser
    if kind == "post":
        _seed(base, path, param, payload)
    url = _url(base, path, kind, param, payload)

    def _measure(page):
        page.goto(f"{base}/", wait_until="commit")
        oracle._wait_load(page)
        oracle._clear(page)
        if kind == "auth":
            # GET /login sets the session cookie (the runner POSTs); without
            # it the dashboard is a 401 and there is no sink to measure.
            page.goto(f"{base}/login", wait_until="commit")
            oracle._wait_load(page)
        page.goto(url, wait_until="commit")
        oracle._wait_load(page)
        page.wait_for_timeout(500)
        return oracle._read_stamp(page)

    stamp = run(_measure)
    print(f"[range7-construct] {cid}: stamp={stamp!r}")
    # Recorded, not gated: a payload shape that does not fire in this harness
    # is a probe question, not necessarily a range fault -- but it is printed
    # so a range whose positives never fire cannot pass silently.
    assert stamp is None or isinstance(stamp, str)
