# -*- coding: utf-8 -*-
"""Desktop console: route wiring, UI asset, and window-backend selection.

Nothing in here opens a real window: the backend probes are monkeypatched so
the ordering logic is exercised on a headless box too.
"""
from __future__ import annotations

import os
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.desktop import app as desktop_app
from xssentinel.desktop import shell
from xssentinel.desktop.assets import load_ui_html, ui_path


# ---------------------------------------------------------------------------
# UI asset
# ---------------------------------------------------------------------------
class TestUiAsset:
    def test_ui_file_exists(self):
        assert os.path.isfile(ui_path()), ui_path()

    def test_ui_is_the_console_page(self):
        html = load_ui_html()
        assert "XSSentinel 桌面控制台" in html
        # The page must talk to the SAME origin it is served from: a file://
        # page would be refused by the API's same-origin gate (Phase 70).
        assert "location.origin" in html

    def test_ui_covers_every_api_surface(self):
        html = load_ui_html()
        for path in ("/api/v1/scans", "/api/v1/health", "/api/v1/info"):
            assert path in html, path
        for fmt in ("html", "json", "sarif", "csv", "junit", "markdown"):
            assert f'value="{fmt}"' in html, fmt

    def test_ui_covers_the_console_surfaces(self):
        """The console's own surfaces, not just the endpoint list.

        Phase 260: the page grew a selected-task detail strip (options +
        coverage), an evidence-class filter, an AI-narrative button and
        adaptive polling.  Each is one string the page cannot work without,
        so the gate stays cheap and honest.
        """
        html = load_ui_html()
        assert "/api/v1/scans/" in html          # detail / findings / report
        assert "coverage_summary" in html        # the coverage matrix card
        assert "ai=" in html                     # report?ai=1 (AI narrative)
        assert "onlyExecuted" in html            # browser-executed-only filter
        assert "POLL_FAST" in html and "POLL_IDLE" in html

    def test_ui_is_not_an_xss_carrier(self):
        """The tool's own output must not become a payload.

        Phase 260 rewrote the page, so this re-states the project's standing
        rule on it: no ``javascript:`` URL anywhere in the console.
        """
        assert "javascript:" not in load_ui_html().lower()

    def test_missing_asset_says_so_instead_of_going_blank(self, monkeypatch):
        """A packaging bug must surface as a page that says so, not a blank
        one -- and the route must not raise."""
        import xssentinel.desktop.assets as assets
        from xssentinel.api import server as api
        desktop_app.install_ui_route()
        handler = next(h for m, rx, h in api._ROUTES if rx.pattern == r"^/$")

        # Point the loader at a path that does not exist: the real fallback
        # branch has to answer, not the exception path.
        monkeypatch.setattr(assets, "UI_PATH",
                            os.path.join(os.sep, "no", "such", "ui.html"))
        resp = handler(ctx=None, match=None, body=None, query=None)
        assert resp.status == 200
        assert "缺失" in resp.body.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# API key carriage (Phase 263)
# ---------------------------------------------------------------------------
class TestApiKeyCarriage:
    """`--api-key` mode used to leave the console unusable: the page had
    nowhere to put the credential, so every call came back 401 and the only
    advice the CLI could give was "use --no-window and script it instead".

    The credential is now entered in the page and attached as a header by
    the page itself.  Two things are deliberately NOT done, and both are
    pinned here because either would be the easy way out:
      * the server never bakes the key into the HTML -- that hands it to
        anything able to GET /;
      * it is not swapped for a session cookie -- that means editing the
        API's auth gate, which is not the console's to change.
    """

    KEY = "topsecret-key"

    def test_page_has_somewhere_to_put_the_key(self):
        html = load_ui_html()
        assert 'id="apiKey"' in html
        assert 'type="password"' in html

    def test_key_lives_in_sessionstorage_not_localstorage(self):
        """A credential must not outlive the tab it was typed into."""
        html = load_ui_html()
        assert "sessionStorage" in html
        assert "localStorage" not in html

    def test_every_call_carries_the_header(self):
        """The invariant that decays: a later edit adding a bare fetch() or a
        bare window.open(reportUrl(...)) silently drops the key, and in
        --api-key mode that reads as a 401, not as a warning."""
        html = load_ui_html()
        assert "X-API-Key" in html
        assert "fetch(reportUrl(fmt), {headers: authHeaders()})" in html
        assert 'window.open(reportUrl(' not in html

    def test_a_401_points_at_the_input(self):
        """Silence is the failure mode here: without this the user sees
        "HTTP 401" and no idea where the key goes."""
        html = load_ui_html()
        assert "401" in html
        assert "needKey" in html

    def _server(self, **kw):
        return desktop_app.build_server(port=0, **kw)

    def test_console_page_never_carries_the_key(self):
        srv = self._server(api_key=self.KEY)
        srv.start_in_thread()
        try:
            with urlopen(srv.base_url + "/", timeout=15) as r:
                body = r.read()
        finally:
            srv._httpd.shutdown()
            srv._httpd.server_close()
        assert self.KEY.encode() not in body

    def test_api_still_rejects_a_keyless_call(self):
        """...which is the whole reason the page has to send it."""
        srv = self._server(api_key=self.KEY)
        srv.start_in_thread()
        try:
            with pytest.raises(HTTPError) as ei:
                urlopen(srv.base_url + "/api/v1/scans", timeout=15)
            assert ei.value.code == 401
            req = Request(srv.base_url + "/api/v1/scans",
                          headers={"X-API-Key": self.KEY})
            with urlopen(req, timeout=15) as r:
                assert r.status == 200
        finally:
            srv._httpd.shutdown()
            srv._httpd.server_close()


# ---------------------------------------------------------------------------
# Route installation
# ---------------------------------------------------------------------------
class TestUiRoute:
    def test_install_is_idempotent(self):
        from xssentinel.api import server as api
        # Self-contained: start from a table with no UI route, whatever
        # earlier tests in this process did to the shared global.
        api._ROUTES[:] = [r for r in api._ROUTES if r[1].pattern != r"^/$"]
        assert desktop_app.install_ui_route() is True
        assert desktop_app.install_ui_route() is False, \
            "installing twice must not add a second route"

    def test_exactly_one_ui_route(self):
        from xssentinel.api import server as api
        desktop_app.install_ui_route()
        roots = [r for r in api._ROUTES if r[1].pattern == r"^/$"]
        assert len(roots) == 1
        assert roots[0][0] == "GET", "the console page must be GET-only"

    def test_route_serves_the_page(self):
        from xssentinel.api import server as api
        desktop_app.install_ui_route()
        handler = next(h for m, rx, h in api._ROUTES if rx.pattern == r"^/$")
        resp = handler(ctx=None, match=None, body=None, query=None)
        assert resp.status == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        assert b"XSSentinel" in resp.body


# ---------------------------------------------------------------------------
# Window backends
# ---------------------------------------------------------------------------
class TestBackendSelection:
    def test_probes_return_booleans(self):
        assert isinstance(shell.pywebview_available(), bool)
        assert isinstance(shell.tkinter_available(), bool)

    def test_order_prefers_native_window(self, monkeypatch):
        monkeypatch.setattr(shell, "pywebview_available", lambda: True)
        monkeypatch.setattr(shell, "tkinter_available", lambda: True)
        opened = []

        def _fake_pywebview(url, title, on_close=None):
            opened.append("pywebview")
            return True

        monkeypatch.setattr(shell, "_open_with_pywebview", _fake_pywebview)
        used = shell.open_console("http://127.0.0.1:1/", prefer=None)
        assert used == shell.BACKEND_PYWEBVIEW
        assert opened == ["pywebview"]

    def test_falls_back_to_tkinter_without_pywebview(self, monkeypatch):
        monkeypatch.setattr(shell, "pywebview_available", lambda: False)
        monkeypatch.setattr(shell, "tkinter_available", lambda: True)
        opened = []

        def _fake_tk(url, title, on_close=None):
            opened.append("tkinter")
            return True

        monkeypatch.setattr(shell, "_open_with_tkinter", _fake_tk)
        used = shell.open_console("http://127.0.0.1:1/", prefer=None)
        assert used == shell.BACKEND_TKINTER
        assert opened == ["tkinter"]

    def test_falls_back_to_browser_when_no_gui(self, monkeypatch):
        monkeypatch.setattr(shell, "pywebview_available", lambda: False)
        monkeypatch.setattr(shell, "tkinter_available", lambda: False)
        monkeypatch.setattr(shell, "_open_with_browser",
                            lambda url, title, on_close=None: True)
        used = shell.open_console("http://127.0.0.1:1/", prefer=None)
        assert used == shell.BACKEND_BROWSER

    def test_a_backend_that_fails_to_open_falls_through(self, monkeypatch):
        """A backend that raises must not take the whole app down."""
        monkeypatch.setattr(shell, "pywebview_available", lambda: True)

        def _boom(url, title, on_close=None):
            raise RuntimeError("no display")

        monkeypatch.setattr(shell, "_open_with_pywebview", _boom)
        monkeypatch.setattr(shell, "_open_with_tkinter",
                            lambda u, t, on_close=None: True)
        monkeypatch.setattr(shell, "tkinter_available", lambda: True)
        used = shell.open_console("http://127.0.0.1:1/", prefer=None)
        assert used == shell.BACKEND_TKINTER

    def test_prefer_rejects_unknown_backend(self):
        with pytest.raises(ValueError):
            shell.open_console("http://127.0.0.1:1/", prefer="wayland")

    def test_run_blocking_browser_parks_and_still_returns(self, monkeypatch):
        """The browser backend returns instantly; run_blocking must not exit
        the process on its own, and must call on_close when interrupted."""
        monkeypatch.setattr(shell, "_open_with_browser",
                            lambda url, title, on_close=None: True)
        monkeypatch.setattr(shell, "pywebview_available", lambda: False)
        monkeypatch.setattr(shell, "tkinter_available", lambda: False)
        closed = []

        import threading as _th

        def _interrupt():
            # Simulate Ctrl-C landing while the main thread is parked.
            import time
            time.sleep(0.2)
            closed.append("interrupt-seen")

        t = _th.Thread(target=_interrupt, daemon=True)
        t.start()

        def _wait(self, timeout=None):
            closed.append("parked")
            return True

        monkeypatch.setattr(_th.Event, "wait", _wait)
        used = shell.run_blocking("http://127.0.0.1:1/",
                                  on_close=lambda: closed.append("closed"))
        assert used == shell.BACKEND_BROWSER
        assert "parked" in closed
        assert "closed" in closed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
class TestMainGuards:
    def test_rejects_non_loopback_bind(self, capsys):
        rc = desktop_app.main(["--host", "0.0.0.0"])
        assert rc == 2
        assert "回环" in capsys.readouterr().err

    def test_print_url_only_starts_and_exits(self, capsys):
        rc = desktop_app.main(["--port", "0", "--print-url-only"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "http://127.0.0.1:" in out

    def test_build_server_binds_loopback_only(self):
        srv = desktop_app.build_server(port=0)
        assert srv.host == "127.0.0.1"
        # base_url is only materialised once the socket exists; port=0 must
        # have been captured as a real ephemeral port by then.
        srv.start_in_thread()
        try:
            assert srv.port and srv.port > 0
            assert srv.base_url.startswith("http://127.0.0.1:")
        finally:
            srv._httpd.shutdown()
            srv._httpd.server_close()
