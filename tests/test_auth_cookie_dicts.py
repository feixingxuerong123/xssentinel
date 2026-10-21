"""Phase 174: the auth cookie dicts handed to Playwright must not mix `url`
with `path`.

Symptom that led here: every DOM analysis logged

    dom: auth cookie apply failed
    playwright Error: BrowserContext.add_cookies:
                     Cookie should have either url or path

...for a cookie that plainly had a ``path``.  The real rule (measured against
the installed Playwright one shape at a time) is that ``url`` and ``path`` are
MUTUALLY EXCLUSIVE:

    {url}                 -> accepted
    {domain, path}        -> accepted
    {url, path}           -> REJECTED
    {url, domain, path}   -> REJECTED

The batch is rejected as a whole and the exception is swallowed into a debug
line, so the browser session stayed silently anonymous: an authenticated scan
rendered 403 route shells and every sink behind a login was invisible
(measured in Phase 173 on Juice Shop's server-side XSS challenge).

These tests pin the shape, and -- when Playwright is importable -- prove that
the pre-174 shape really is rejected, so the gate is not vacuous.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.dom_engine import _auth_cookie_dicts

URL = "http://127.0.0.1:3000/#/administration"


def test_domainless_cookie_uses_url_and_no_path():
    """A manual --cookie jar carries no domain; Playwright then wants `url`
    alone -- adding `path` is what made add_cookies throw."""
    got = _auth_cookie_dicts(
        [{"name": "token", "value": "v", "domain": None, "path": "/"}], URL)
    assert got == [{"name": "token", "value": "v",
                    "url": "http://127.0.0.1:3000"}]
    assert "path" not in got[0], got


def test_empty_domain_is_treated_as_domainless():
    got = _auth_cookie_dicts(
        [{"name": "token", "value": "v", "domain": "", "path": "/"}], URL)
    assert "path" not in got[0], got
    assert got[0]["url"] == "http://127.0.0.1:3000"


def test_domain_cookie_uses_domain_and_path():
    got = _auth_cookie_dicts(
        [{"name": "token", "value": "v", "domain": "example.com",
          "path": "/x"}], URL)
    assert got == [{"name": "token", "value": "v",
                    "domain": "example.com", "path": "/x"}]
    assert "url" not in got[0], got


def test_default_path_when_domain_present_and_path_missing():
    got = _auth_cookie_dicts(
        [{"name": "token", "value": "v", "domain": "example.com"}], URL)
    assert got[0]["path"] == "/", got


def test_missing_value_becomes_empty_string():
    """Playwright rejects `undefined`; it wants a string."""
    got = _auth_cookie_dicts([{"name": "token", "domain": None}], URL)
    assert got[0]["value"] == "", got


class TestPlaywrightAcceptsTheShape:
    """The reverse check: the old shape must actually blow up."""

    def test_engine_shape_accepted_and_old_shape_rejected(self):
        pytest.importorskip("playwright.sync_api")
        from playwright.sync_api import sync_playwright

        good = _auth_cookie_dicts(
            [{"name": "token", "value": "v", "domain": None, "path": "/"}], URL)
        bad = [{"name": "token", "value": "v", "path": "/",
                "url": "http://127.0.0.1:3000"}]        # the pre-174 shape

        with sync_playwright() as p:
            try:
                b = p.chromium.launch(args=["--no-sandbox"])
            except Exception as e:  # noqa: BLE001
                pytest.skip(f"chromium unavailable: {e}")
            try:
                ctx = b.new_context()
                ctx.add_cookies(good)
                assert any(c["name"] == "token" for c in ctx.cookies()), \
                    "the cookie did not land in the context"

                ctx2 = b.new_context()
                with pytest.raises(Exception) as ei:
                    ctx2.add_cookies(bad)
                assert "url or path" in str(ei.value), str(ei.value)
            finally:
                b.close()


# ---------------------------------------------------------------------------
# Phase 289: the operator `-b/--cookie` jar -> browser dicts path
#
# The #5 close (Juice Shop API-only XSS) depends on this exact path: the
# welcome dialog that intercepts the product-card click is suppressed by
# the cookie `welcomebanner_status=dismiss`, seeded via `-b`.  The
# conversion itself was an inline comprehension in __main__ (untestable);
# it is now `_jar_cookie_dicts`, and these tests pin both halves -- the
# conversion AND that its output survives the engine's url-vs-path rule.
# ---------------------------------------------------------------------------

class _FakeCookie:
    def __init__(self, name, value, domain=None, path="/"):
        self.name, self.value = name, value
        self.domain, self.path = domain, path


class _FakeJar:
    def __init__(self, cookies):
        self.cookies = cookies


def test_operator_cookie_reaches_the_browser_dicts():
    """A domainless `-b` cookie becomes a Playwright-valid dict (url form,
    no path) -- the shape _auth_cookie_dicts is documented to want."""
    from xssentinel.__main__ import _jar_cookie_dicts
    jar = _FakeJar([_FakeCookie("welcomebanner_status", "dismiss")])
    dicts = _jar_cookie_dicts(jar)
    assert dicts == [{"name": "welcomebanner_status", "value": "dismiss",
                      "domain": None, "path": "/"}]
    engine_dicts = _auth_cookie_dicts(dicts, URL)
    assert engine_dicts == [{"name": "welcomebanner_status",
                             "value": "dismiss",
                             "url": "http://127.0.0.1:3000"}]
    assert "path" not in engine_dicts[0], engine_dicts


def test_jar_conversion_handles_session_and_operator_cookies_together():
    """Login cookies (domain-bearing) and operator cookies (domainless)
    ride in the same jar and must ALL reach the browser -- the login half
    is what keeps authenticated sinks visible (Phase 173/174), the
    operator half is what suppresses UI-state gates (Phase 289)."""
    from xssentinel.__main__ import _jar_cookie_dicts
    jar = _FakeJar([
        _FakeCookie("token", "jwt", domain="127.0.0.1", path="/"),
        _FakeCookie("welcomebanner_status", "dismiss"),
        _FakeCookie("blank", ""),                      # value=None -> ""
    ])
    dicts = _jar_cookie_dicts(jar)
    assert len(dicts) == 3
    assert dicts[2] == {"name": "blank", "value": "",
                        "domain": None, "path": "/"}
    engine_dicts = _auth_cookie_dicts(dicts, URL)
    names = sorted(d["name"] for d in engine_dicts)
    assert names == ["blank", "token", "welcomebanner_status"]
    by_name = {d["name"]: d for d in engine_dicts}
    assert by_name["token"]["domain"] == "127.0.0.1"      # domain form
    assert "url" not in by_name["token"]
    # domainless cookies get the ORIGIN (scheme://netloc), not the full
    # URL with its route -- _auth_cookie_dicts strips the path/hash.
    origin = "http://127.0.0.1:3000"
    assert by_name["welcomebanner_status"]["url"] == origin  # url form
    assert "domain" not in by_name["welcomebanner_status"]


def test_jar_conversion_none_session_is_empty():
    from xssentinel.__main__ import _jar_cookie_dicts
    assert _jar_cookie_dicts(None) == []
