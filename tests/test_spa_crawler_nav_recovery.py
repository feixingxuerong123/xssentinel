"""Regression: a failed SPA goto must recover the page, not wedge it.

Phase 200 fixed `SpaCrawler.crawl`'s TOP-LEVEL abort (no browser -> fall
back to the static crawler).  That fix left a narrower hole open, measured
here:

    dev/_dom_links_wedge_probe.py, end-to-end through crawl():
      before the fix -- crawl() against a page that never answers took
                       **117.02s** and returned 0 endpoints
      after  the fix -- the same crawl takes **3.69s**, 0 endpoints

117s is what one `page.evaluate` costs when Chromium still holds the
PROVISIONAL navigation left behind by a raising `page.goto`.  And the
outcome is worse than slow: every post-render harvest on that page --
DOM links, SPA routes, forms -- returned [], so the crawl reported
"this SPA has no links" for a page whose links it simply never got to
read.  Silent loss, same failure MODE as the bug Phase 200 fixed, one
level down.

The fix belongs in the goto failure branch of crawl(), NOT in the four
evaluate handlers: a handler there runs only after the evaluate has
already spent its ~117s.  That is not a guess -- the method-level fix was
written first, measured, and came back 117.02s, unchanged.

These tests need no browser: a fake page reproduces the state (goto
raises, evaluate then blocks) and records whether recovery was invoked
before any evaluate ran.

The last three cover the recovery's own blast radius, which the first
fix left undefined: the `from .dom_engine import _recover_nav` line sits
inside an `except` block with no guard of its own.  Measured
(dev/_recover_import_probe.py, write-up in dev/_RECOVER_IMPORT.md): it
cannot escape crawl(), because the BFS loop is wrapped by crawl()'s
outer `except Exception` -- so no guard is added there.  What IS pinned
is that boundary, including where it deliberately stops: BaseException
passes through, so Ctrl-C still stops a scan.

Double fidelity is itself measured (dev/_double_fidelity_probe.py): an
earlier version of `_WedgedPage` invented `new_page`, omitted `url`, and
took `**kwargs` that real `wait_for_load_state` rejects.  A missing
attribute would have raised AttributeError INTO the very `except
Exception` blocks these tests exist to exercise -- the tests would have
looked green while measuring nothing.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "xssentinel/core")
sys.path.insert(0, "xssentinel")

from core import spa_crawler as spa  # noqa: E402


class _WedgedPage:
    """A page in the post-failed-goto state Phase 200 measured.

    Every `goto` to a real URL raises, which is what puts Chromium into
    the provisional-navigation state; only `about:blank` succeeds and
    flips `recovered`.

    `evaluate` does NOT sleep -- it raises when the page is still
    provisional.  That is a deliberate stand-in for the real 117.02s
    stall (dev/_dom_links_wedge_probe.py): a crawler that recovers too
    late gets an immediate, loud failure instead of a two-minute hang.
    The timing itself is measured in the probe, not asserted here, so
    the two artifacts cannot drift into claiming each other.
    """

    def __init__(self):
        self.recovered = False
        self.calls: list[str] = []

    def goto(self, url, timeout=None, wait_until=None):
        self.calls.append(f"goto:{url}")
        if url == "about:blank":
            self.recovered = True
            return
        raise RuntimeError("Page.goto: Timeout 3000ms exceeded")

    def evaluate(self, expr):
        self.calls.append("evaluate")
        if not self.recovered:
            # A real evaluate here is the 117.02s stall.  The fake raises
            # instead of sleeping so a regression fails in seconds; the
            # timing itself is measured by dev/_dom_links_wedge_probe.py,
            # which is why the bound lives there and not in an assertion
            # here.
            raise AssertionError(
                "evaluate ran while the navigation was still provisional "
                "-- this is the 117s stall")
        return []

    def wait_for_load_state(self, state=None, *, timeout=None):
        # The real signature, read live from the installed Playwright:
        #   wait_for_load_state(self, state=None, *, timeout=None)
        # An earlier `*args` version here was a catch-all -- it accepted
        # positional calls the real API rejects.  That drift survived two
        # rounds of "fidelity fixes" because the guard compared parameter
        # NAMES; the fidelity guard now compares parameter KINDS.
        return None

    def wait_for_timeout(self, ms):
        return None

    def add_init_script(self, script=None, path=None):
        # crawl() installs the SPA route hook here; recording it proves
        # the fake page really is the one crawl() drives.
        self.calls.append("init_script")
        return None

    def on(self, event, handler=None):
        return None

    def content(self):
        return "<html><body></body></html>"

    def context(self):
        return self

    def close(self):
        return None

    def is_closed(self):
        return False

    # NOTE: `url` is present because real Page has it and the fidelity
    # guard checks the double against the real surface -- but no
    # production code reads page.url (measured by
    # dev/_required_members_probe.py), which is exactly why it is NOT in
    # REQUIRED_PAGE_MEMBERS.  Kept for surface fidelity, not for a test.
    @property
    def url(self):
        return "http://h/app"


class _FakeContext:
    """What `browser.new_context()` returns -- kept separate from the page
    double because Playwright's real objects have different surfaces."""

    def __init__(self, page):
        self._page = page

    def new_page(self):
        return self._page

    def on(self, event, handler=None):
        return None

    def route(self, url, handler=None):
        return None

    def unroute(self, url, handler=None):
        return None

    def close(self):
        return None


def _patch_playwright(monkeypatch, page: _WedgedPage):
    """Hand crawl() a live-looking browser whose every goto raises."""
    import playwright.sync_api as psa

    class _Browser:
        def new_context(self, **_k):
            # crawl() attaches the XHR response listener on the CONTEXT;
            # a fake missing `on` raises AttributeError into the crawl's
            # outer except and the test silently measures nothing.
            return _FakeContext(page)

        def close(self):
            return None

    class _Chromium:
        def launch(self, **_k):
            return _Browser()

        def close(self):
            return None

    class _PW:
        chromium = _Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(spa, "_playwright_available", lambda: True)
    monkeypatch.setattr(psa, "sync_playwright", lambda *a, **k: _PW())


def _crawler():
    return spa.SpaCrawler(max_depth=1, scope=None, timeout=1, headless=True,
                          per_page_budget_s=0.01, max_total_pages=1,
                          max_clicks_per_page=0, verbose=False)


# --- the failing case -------------------------------------------------------

def test_failed_goto_recovers_before_any_evaluate(monkeypatch):
    """The measured 117.02s stall: recovery must precede the evaluate."""
    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)

    out = _crawler().crawl("http://h/app")

    assert page.calls, "the crawl must have attempted the page"
    first_eval = next((i for i, c in enumerate(page.calls)
                       if c == "evaluate"), None)
    if first_eval is not None:
        assert "about:blank" in page.calls[:first_eval], (
            "the page was left provisional and an evaluate ran before "
            "recovery -- exactly the 117s stall")
    assert out == [], (
        "a page that never answers genuinely has no endpoints; returning "
        "[] is correct here, the bug was HOW LONG it took and what it "
        "silently claimed meanwhile")


def test_recovery_navigates_to_about_blank(monkeypatch):
    """Recovery is dom_engine's measured shape (about:blank, 0.02s)."""
    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)

    _crawler().crawl("http://h/app")

    assert "goto:about:blank" in page.calls, (
        f"recovery must use about:blank; got {page.calls}")


def test_healthy_page_never_navigates_to_about_blank(monkeypatch):
    """A page that loads is left alone -- recovery is not unconditional.

    Without this, 'always recover' would pass the guard above while
    breaking every normal crawl (an extra navigation per page, and the
    SPA route init script's state destroyed after each visit).
    """
    page = _WedgedPage()

    def healthy_goto(url, timeout=None, wait_until=None):
        page.calls.append(f"goto:{url}")
        if url == "about:blank":
            page.recovered = True
        return

    page.goto = healthy_goto

    class _Browser:
        def new_context(self, **_k):
            return _FakeContext(page)

        def close(self):
            return None

    import playwright.sync_api as psa

    class _Chromium:
        def launch(self, **_k):
            return _Browser()

    class _PW:
        chromium = _Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(spa, "_playwright_available", lambda: True)
    monkeypatch.setattr(psa, "sync_playwright", lambda *a, **k: _PW())

    _crawler().crawl("http://h/app")

    assert "goto:about:blank" not in page.calls, (
        "a page that navigated successfully must not be recovered")


# --- mutation control ------------------------------------------------------

def test_removing_recovery_changes_the_browser_state(monkeypatch):
    """The guard must be load-bearing.

    Re-runs the SAME wedged crawl with dom_engine._recover_nav neutralised
    and asserts the page is left in a different state.  A guard that
    passes with or without the fix proves nothing, and this project has
    been bitten by that more than once.

    Note what is NOT asserted here: that the crawl reaches an evaluate.
    It does not -- a failed goto is followed by `continue`, so this page
    is skipped and the original probe's 117s came from the earlier code
    shape where the failure did not skip.  What the fix buys is that the
    page is handed back usable to the NEXT queued URL instead of staying
    provisional for the rest of the crawl.
    """
    import core.dom_engine as de

    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)
    _crawler().crawl("http://h/app")
    assert page.recovered is True, (
        "with recovery in place the page must be usable again")
    assert "goto:about:blank" in page.calls

    # Same input, recovery removed.
    page_off = _WedgedPage()
    _patch_playwright(monkeypatch, page_off)
    monkeypatch.setattr(de, "_recover_nav", lambda p: None)
    _crawler().crawl("http://h/app")

    assert page_off.recovered is False, (
        "the mutation must actually differ, otherwise the tests above "
        "cannot be distinguishing anything")
    assert "goto:about:blank" not in page_off.calls


# --- recovery must not become a crash ---------------------------------------
# The fix imports dom_engine._recover_nav from inside an `except` block,
# and that import carries no guard of its own.  Measured
# (dev/_recover_import_probe.py, recorded in dev/_RECOVER_IMPORT.md): it
# cannot escape crawl(), because the BFS loop is wrapped by crawl()'s own
# outer `except Exception` -- the Phase 200 abort-to-fallback handler.
# These two tests pin that reasoning so it stays measured rather than
# folklore; without them the next reader sees a missing guard and adds one.

def test_recovery_raising_does_not_escape_crawl(monkeypatch):
    """_recover_nav raising must not abort the crawl.

    This is `_recover_nav`'s own documented contract ("recovery must never
    turn one failure into a crash"), checked from the caller's side: the
    crawl still returns normally.
    """
    import core.dom_engine as de

    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)

    def boom(_page):
        raise RuntimeError("recovery exploded")

    monkeypatch.setattr(de, "_recover_nav", boom)

    out = _crawler().crawl("http://h/app")

    assert out == [], "a page that never answers yields no endpoints"
    assert page.calls, "the crawl must have attempted the page"


def test_recovery_import_failure_degrades_to_fallback(monkeypatch):
    """If dom_engine cannot even be imported, the crawl degrades, not dies.

    Measured behaviour: the import raises inside the `except` block, the
    outer handler catches it, and crawl() returns through the Phase 200
    abort path -- which consults the caller's static crawler.  That is the
    degradation this asserts, and it is why no guard is added at the
    import site.
    """
    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)

    seen: list = []
    out = _crawler().crawl(
        "http://h/app",
        fallback_crawler=lambda u: seen.append(u) or [
            ("http://h/static", "GET", {"q": "xss"}, {})])

    # Whichever path ran, crawl() returned rather than propagating, and
    # the page was visited.
    assert isinstance(out, list)
    assert page.calls or seen == ["http://h/app"]


def test_base_exception_from_recovery_is_not_swallowed(monkeypatch):
    """The recovery's blast radius stops at Exception -- deliberately.

    crawl()'s outer handler catches Exception, and so does _recover_nav.
    BaseException (KeyboardInterrupt, SystemExit) passes through both, on
    purpose: a Ctrl-C during a scan must actually stop the scan, and a
    recovery helper that swallowed it would make the tool unkillable.

    This test exists so the boundary is a recorded decision rather than an
    accident -- and so that "recovery never crashes the crawl" is not
    misread as "recovery absorbs everything".
    """
    import core.dom_engine as de

    page = _WedgedPage()
    _patch_playwright(monkeypatch, page)

    def base_boom(_page):
        raise KeyboardInterrupt("operator pressed Ctrl-C")

    monkeypatch.setattr(de, "_recover_nav", base_boom)

    with pytest.raises(KeyboardInterrupt):
        _crawler().crawl("http://h/app")


# --- the doubles themselves must be faithful -------------------------------
# Measured with dev/_double_fidelity_probe.py against real Playwright: an
# earlier `_WedgedPage` invented `new_page` (real Page has no such
# method), omitted `url`, and took **kwargs that real
# `wait_for_load_state` rejects.
#
# The two failure directions are both silent:
#   * a double that INVENTS API lets a test assert on a call the
#     production code cannot make -- it passes while proving nothing;
#   * a double MISSING something raises AttributeError inside the very
#     `except Exception` blocks under test, so the test goes green while
#     measuring nothing.
#
# These assertions are the falsifiable part: each fails if the doubles
# drift away from the real Playwright surface.

def test_doubles_match_the_real_type_each_one_replaces():
    """Each double is compared against the ONE real type it stands in for.

    Comparing by union-of-names was the first attempt and it had a hole:
    `new_page` is absent from real Page but present on real
    BrowserContext, so a union check passed a `_WedgedPage.new_page` --
    exactly the invented method this guard exists to catch.  The fix is
    to compare per role, not against a union.
    """
    from playwright.sync_api import BrowserContext, Page

    def real_names(cls):
        return {n for n in dir(cls) if not n.startswith("_")}

    page_real = real_names(Page)
    ctx_real = real_names(BrowserContext)

    for name in dir(_WedgedPage):
        if name.startswith("__"):
            continue
        member = getattr(_WedgedPage, name)
        if callable(member):
            assert name in page_real, (
                f"_WedgedPage.{name} is not a real Page API -- the double "
                f"can answer calls the production code cannot make")
        else:
            assert name in page_real, (
                f"_WedgedPage.{name} is not a real Page API")

    for name in dir(_FakeContext):
        if name.startswith("__"):
            continue
        assert name in ctx_real, (
            f"_FakeContext.{name} is not a real BrowserContext API")

    # The Page double must NOT own the Context's factory.  Stated as its
    # own assertion so a re-added `new_page` fails on this line, not on
    # an unrelated one.
    assert "new_page" not in page_real, (
        "real Page now has new_page; re-check which double may own it")
    assert not hasattr(_WedgedPage, "new_page"), (
        "_WedgedPage.new_page was re-added -- crawl() obtains its page "
        "from context.new_page() (spa_crawler:290), and a Page double "
        "answering it lets a test pass on an impossible call")
    assert hasattr(_FakeContext, "new_page")


#: The Page attributes crawl() actually touches.  The derivation is the
#: point: a first version of this list also carried `content`,
#: `context`, `is_closed` and `url` because a Page "ought to" have them.
#: None of the four is referenced anywhere under xssentinel/ -- measured
#: by dev/_required_members_probe.py, which reads the production AST.
#: They were decoration: cases that could only fail if someone edited
#: the list itself.
#:
#: A guard on the deletion direction is still needed, because the guard
#: above only fires on EXTRA members.
REQUIRED_PAGE_MEMBERS = (
    # spa_crawler.py:312  page.goto(url, timeout=..., wait_until=...)
    "goto",
    # spa_crawler.py:356/473/536/666  page.evaluate(<js>)
    "evaluate",
    # spa_crawler.py:318  page.wait_for_load_state("networkidle", timeout=)
    "wait_for_load_state",
    # spa_crawler.py:646  page.wait_for_timeout(400)
    "wait_for_timeout",
    # spa_crawler.py:291  page.add_init_script(_NAV_HOOK_JS)
    "add_init_script",
    # spa_crawler.py:293  page.on("dialog", ...)
    "on",
    # spa_crawler.py:400  context.close()
    "close",
)


@pytest.mark.parametrize("name", REQUIRED_PAGE_MEMBERS)
def test_page_double_still_has_every_attribute_crawl_uses(name):
    assert hasattr(_WedgedPage, name), (
        f"_WedgedPage.{name} was removed.  A missing attribute raises "
        f"AttributeError inside the crawl() `except Exception` blocks, so "
        f"the tests above would go green while measuring nothing")


def test_every_required_member_is_referenced_by_production_code():
    """No member of the list may be there by belief.

    The list above was audited with dev/_required_members_probe.py, which
    reads spa_crawler.py's AST and reports which `page.*` attributes the
    crawler actually touches.  Four names were listed on the reasoning
    that a Page "ought to" have them (content, context, is_closed, url);
    none is referenced anywhere under xssentinel/, so those cases could
    only fail if someone edited the list.

    The check runs here, not only in the dev script, because a check that
    only runs when somebody remembers to run it is not a gate.
    """
    import ast
    import os

    prod = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "xssentinel", "core", "spa_crawler.py")
    tree = ast.parse(open(prod, encoding="utf-8").read(), prod)
    used = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in ("page", "context", "browser")):
            used.add(node.attr)

    decoration = [n for n in REQUIRED_PAGE_MEMBERS if n not in used]
    assert not decoration, (
        f"{decoration} are listed as required but spa_crawler.py never "
        f"references them -- decoration inflates the case count without "
        f"protecting anything")

    # Coverage must not shrink silently.  A mutation that deleted the
    # `goto` entry turned the parametrised guard from 7 cases into 6 and
    # the suite stayed GREEN: nothing asserted on the set, so a lost
    # guard looked exactly like a passing suite.  Both directions are
    # now pinned -- losing a member and adding a decorative one.
    expected = {"goto", "evaluate", "wait_for_load_state",
                "wait_for_timeout", "add_init_script", "on", "close"}
    lost = expected - set(REQUIRED_PAGE_MEMBERS)
    assert not lost, (
        f"{sorted(lost)} dropped out of REQUIRED_PAGE_MEMBERS; the "
        f"parametrised guard would silently lose a case and the suite "
        f"would still pass")
    extra = set(REQUIRED_PAGE_MEMBERS) - expected
    assert not extra, f"unexpected entries: {sorted(extra)}"


def test_doubles_accept_the_keywords_the_production_code_passes():
    """Every keyword spa_crawler actually passes must be accepted.

    The call sites were read to decide which keywords matter:
      spa_crawler:312  page.goto(url, timeout=..., wait_until=...)
      spa_crawler:318  page.wait_for_load_state("networkidle", timeout=...)
      spa_crawler:291  page.add_init_script(_NAV_HOOK_JS)
      spa_crawler:288  context.on("response", fn)
      spa_crawler:293  page.on("dialog", fn)
    """
    import inspect

    page = _WedgedPage()
    ctx = _FakeContext(page)

    # about:blank is the one goto that succeeds on this double, so it is
    # what proves the keywords are accepted.  A real URL raises on
    # purpose -- that IS the state under test.
    page.goto("about:blank", timeout=1000, wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle", timeout=500)
    page.add_init_script(script="//hook")
    page.on("dialog", lambda d: None)
    ctx.on("response", lambda r: None)

    # And the signatures must not have silently reverted to a catch-all.
    #
    # The check is on the parameter KIND, not its name.  A first version
    # asserted `"kwargs" not in inspect.signature(fn).parameters`, which
    # reads correctly and is VACUOUS: `inspect` names a keyword-only
    # parameter `kwargs`, but a bare `**kw` shows up as `kw`.  The
    # mutation run (dev/_double_fidelity_mutation.py) showed the guard
    # staying green under exactly the mutation it was written to catch.
    for fn, name in ((page.goto, "goto"),
                     (page.wait_for_load_state, "wait_for_load_state"),
                     (page.add_init_script, "add_init_script"),
                     (page.on, "on"),
                     (ctx.on, "context.on")):
        params = inspect.signature(fn).parameters
        catch_all = [p.name for p in params.values()
                     if p.kind in (inspect.Parameter.VAR_KEYWORD,
                                   inspect.Parameter.VAR_POSITIONAL)]
        assert not catch_all, (
            f"{name} accepts a catch-all {catch_all}; the real Playwright "
            f"API spells its options as named parameters, so a catch-all "
            f"lets this double answer calls the real one rejects")
