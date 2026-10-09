# -*- coding: utf-8 -*-
"""Phase 209: a hash-routing SPA's routes must be reachable from its root URL.

Measured on OWASP Juice Shop 20.2.0 (a real Angular SPA, not a fixture of
ours).  A root-URL crawl produced 74 endpoints and **zero** carrying a
fragment; the bundle declares 45 router paths, and the app reads its routes
from ``location.hash``.  Handed ``/#/search?q=apple`` directly, the same
build reports a browser-executed high DOM XSS in 11s.  So the detection was
never the gap -- discovery was: ``extract_endpoints`` returns route paths,
the crawler resolved them with ``urljoin`` into SERVER paths (``/search``),
and a hash-routing client never reads that.

These tests pin the three separate failure surfaces, because each one could
come back on its own:

  1. mining the (route -> query-param) pairing out of the bundle,
  2. registering the endpoint with its fragment intact,
  3. deduping by signature WITHOUT collapsing every route on one host.
"""
from __future__ import annotations

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import js_miner  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402

# The minified shape Angular emits for `router.navigate(['/search'],
# {queryParams:{q:e}})` -- the params object is bound to a variable `i` and
# assigned just before the call, which is why the pairing reads a window.
MINIFIED = (
    "}search(e){if(e){let i={queryParams:{q:e}};"
    "this.ngZone.run(()=>__(this,null,function*(){"
    "return yield this.router.navigate([`/search`],i)}))}}"
)
BASE = "http://spa.test/"


# ---------------------------------------------------- 1. pairing the params --

def test_route_and_query_param_are_paired():
    assert js_miner.spa_query_params(MINIFIED) == {"search": ["q"]}


def test_unminified_spacing_is_paired_too():
    """Plain (un-minified) JS and source-map originals write this shape.  A
    minified-only pattern is what made the first delivery gate fail: the
    fixture looked like an app the scanner could not reach, and the real
    cause was a pattern that only matched one build of one framework."""
    unminified = ("this.router.navigate(['/search'], "
                  "{ queryParams: { q: value } });")
    assert js_miner.spa_query_params(unminified) == {"search": ["q"]}
    assert js_miner.hash_route_urls(unminified, BASE) == [
        "http://spa.test/#/search?q=xss"]


def test_url_is_built_with_the_fragment_and_the_param():
    urls = js_miner.hash_route_urls(MINIFIED, BASE)
    assert urls == ["http://spa.test/#/search?q=xss"]


def test_params_outside_the_navigation_window_are_not_paired():
    """A global "any queryParams object" match would attach every param key
    in the bundle to every route -- plausible-looking URLs that no code
    produces, and a budget sink on a real app."""
    src = ('queryParams:{secretToken:a};' + "x" * 4000 +
           'this.router.navigate([`/search`],i)')
    assert js_miner.spa_query_params(src) == {}


def test_template_routes_are_skipped():
    """:addressId needs a real id, so it is not a probeable URL."""
    src = ("let i={queryParams:{q:e}};"
           "this.router.navigate([`/address/edit/:addressId`],i)")
    assert js_miner.spa_query_params(src) == {}
    assert js_miner.hash_route_urls(src, BASE) == []


def test_non_spa_source_yields_nothing():
    assert js_miner.hash_route_urls("fetch('/api/v1/thing')", BASE) == []
    assert js_miner.hash_route_urls("", BASE) == []


def test_route_count_is_capped():
    src = "".join(
        f'let i={{queryParams:{{q:{n}}}}};'
        f'this.router.navigate([`/r{n}`],i);'
        for n in range(js_miner.MAX_HASH_ROUTES + 8))
    urls = js_miner.hash_route_urls(src, BASE)
    assert len(urls) == js_miner.MAX_HASH_ROUTES, (
        "each hash route is a browser probe pass; the cap is a cost ceiling")


def test_origin_only_is_honoured_and_cross_origin_base_is_rejected():
    assert js_miner.hash_route_urls(MINIFIED, "https://other.example/") == [
        "https://other.example/#/search?q=xss"]
    assert js_miner.hash_route_urls(MINIFIED, "not-a-url") == []


# ------------------------------------------- 2. crawl registers the fragment --

class _FakeResp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": "text/html"}
        self.encoding = "utf-8"
        self.content = text.encode()


class _FakeReq:
    """Maps URLs to canned bodies; records what was asked for."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def get(self, url, params=None, headers=None, **kw):
        self.requested.append(url)
        if url not in self.pages:
            raise OSError(f"no canned page for {url}")
        return _FakeResp(self.pages[url])

    def request(self, method, url, **kw):
        return self.get(url)

    @property
    def attempted_requests(self):
        return len(self.requested)


SPA_SHELL = ('<html><body><app-root></app-root>'
             '<script src="/main.js"></script></body></html>')
SPA_SHELL_WITH_LINKS = ('<html><body><app-root></app-root>'
                        '<a href="/p?q=1">link</a>'
                        '<form action="/c" method="post">'
                        '<input name="note"></form>'
                        '<script src="/main.js"></script></body></html>')


def _spa_scanner():
    pages = {
        "http://spa.test/": SPA_SHELL,
        "http://spa.test/main.js": MINIFIED,
    }
    sc = Scanner(requester=_FakeReq(pages), crawl=True, crawl_depth=1,
                 advanced_layers=False)
    return sc, pages


def test_crawl_registers_the_hash_route_with_its_fragment():
    sc, _ = _spa_scanner()
    endpoints = sc._crawl("http://spa.test/")
    urls = [u for u, _m, _p, _d in endpoints]
    assert "http://spa.test/#/search?q=xss" in urls, (
        "the fragment IS the route; losing it is the whole Phase 209 gap")


def test_crawl_still_registers_ordinary_endpoints():
    """Additivity: linked pages and form fields were endpoints before this
    change and the benchmark depends on them -- the new fragment route must
    not displace them.  (The start page itself is deliberately not in
    ``_crawl``'s output: scan_target carries it as index 0.)"""
    shell = SPA_SHELL_WITH_LINKS
    sc = Scanner(requester=_FakeReq({
        "http://spa.test/": shell,
        "http://spa.test/p": "<html><body>p</body></html>",
        "http://spa.test/main.js": MINIFIED,
    }), crawl=True, crawl_depth=1, advanced_layers=False)
    endpoints = sc._crawl("http://spa.test/")
    urls = [u for u, _m, _p, _d in endpoints]
    assert "http://spa.test/#/search?q=xss" in urls
    assert "http://spa.test/p" in urls
    assert any(u == "http://spa.test/c" and (p or d)
               for u, _m, p, d in endpoints), \
        "the form endpoint must arrive with its fields, as before"


def test_spa_crawler_path_also_gets_the_hash_routes(monkeypatch):
    """The browser crawler is the DEFAULT sync path (crawl_engine=auto with
    Playwright installed) and it never reads the bundle.

    This is the case the first Juice Shop run proved: routes were mined by
    the *static* path only, so with Playwright present the scan registered
    74 endpoints and not one fragment.  Even a browser crawl that finds no
    route at all must still hand the mined routes to the scan.
    """
    from xssentinel.core import spa_crawler as spa_mod

    class _NoRouteCrawler:
        def __init__(self, **kw):
            pass

        def crawl(self, start_url, fallback_crawler=None):
            return []

    monkeypatch.setattr(spa_mod, "SpaCrawler", _NoRouteCrawler)
    sc = Scanner(requester=_FakeReq({
        "http://spa.test/": SPA_SHELL,
        "http://spa.test/main.js": MINIFIED,
    }), crawl=True, crawl_depth=1, advanced_layers=False)
    urls = [u for u, _m, _p, _d in sc._crawl_spa("http://spa.test/")]
    assert "http://spa.test/#/search?q=xss" in urls


# ------------------------------------- 3. dedupe must not collapse routes --

def test_fragment_endpoints_are_capped_across_all_scripts():
    """The union, not each source, must respect the cap.

    Found by re-reading my own wiring: `hash_urls` accumulates the inline
    block AND up to 8 external scripts, each of which `hash_route_urls` caps
    at MAX_HASH_ROUTES -- so a page whose bundles each declare routes would
    register ~100 fragment endpoints and pay a browser probe pass for every
    one.  Per-source caps are not a cost ceiling.
    """
    def nav(route):
        return (f'let i={{queryParams:{{q:{route}}}}};'
                f'this.router.navigate([`/{route}`], i);')

    shell = ('<html><body>'
             + "".join(f'<script src="/b{k}.js"></script>' for k in range(8))
             + '</body></html>')
    pages = {"http://spa.test/": shell}
    for k in range(8):
        pages[f"http://spa.test/b{k}.js"] = "".join(nav(f"r{k}_{j}")
                                                    for j in range(6))
    sc = Scanner(requester=_FakeReq(pages), crawl=True, crawl_depth=1,
                 advanced_layers=False)
    urls = [u for u, _m, _p, _d in sc._crawl("http://spa.test/")
            if "#" in u]
    assert len(urls) <= js_miner.MAX_HASH_ROUTES, (
        f"registered {len(urls)} fragment endpoints from 8 bundles; the cap "
        "must apply to the union or it is not a cost ceiling")


# ------------------------------------- 3. dedupe must not collapse routes --

def test_signature_dedupe_keeps_distinct_hash_routes():
    eps = [
        ("http://h/#/search?q=xss", "GET", {}, {}),
        ("http://h/#/basket?id=xss", "GET", {}, {}),
    ]
    kept = Scanner._dedupe_endpoint_signatures(list(eps))
    assert len(kept) == 2, (
        "same method+host+path, different client-side route: the fragment is "
        "the only thing that distinguishes them")


def test_signature_dedupe_still_collapses_query_values():
    """Phase 32's original purpose must survive: /search?q=1 and ?q=2 are one
    sink, and dropping that would explode the request budget."""
    eps = [
        ("http://h/search?q=1", "GET", {"q": "1"}, {}),
        ("http://h/search?q=2", "GET", {"q": "2"}, {}),
    ]
    assert len(Scanner._dedupe_endpoint_signatures(eps)) == 1


# -------------------------------------- wiring guards (both engines, always) --

def _engine_source_files(module_names):
    """Read the engine's modules off disk, enumerated BY NAME.

    A glob would let a future file split hide a call site the same way the
    last one nearly did (tests/test_async_wiring.py carries that lesson).
    """
    out = {}
    for name in module_names:
        path = os.path.join(ROOT, "xssentinel", "core", f"{name}.py")
        assert os.path.exists(path), f"engine module moved: {path}"
        with open(path, "r", encoding="utf-8") as f:
            out[name] = f.read()
    assert len(out) == len(module_names)
    return out


SYNC_CRAWL = ("scanner_crawl",)
ASYNC_CRAWL = ("async_scanner_crawl", "async_scanner", "async_scanner_common",
               "async_scanner_layers", "async_scanner_verify")


def _call_sites(src: str, func: str) -> list:
    """Attribute names of `js_miner.<func>(...)` call sites in one file."""
    hits = []
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == func
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "js_miner"):
            hits.append(node.lineno)
    return hits


def test_both_engines_discover_hash_routes():
    """Async has no browser crawl of its own, but it shares the endpoint
    mining -- and this repo has paid three times for "sync got fixed and
    async did not"."""
    sync = _engine_source_files(SYNC_CRAWL)["scanner_crawl"]
    async_files = _engine_source_files(ASYNC_CRAWL)
    assert _call_sites(sync, "hash_route_urls"), \
        "sync crawl no longer registers discovered SPA routes"
    found = {n: _call_sites(s, "hash_route_urls")
             for n, s in async_files.items() if _call_sites(s, "hash_route_urls")}
    assert found, "async crawl no longer registers discovered SPA routes"


def _function_body(src: str, name: str):
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == name:
            return node
    return None


def _calls_in(func, attr: str, owner: str | None = None) -> bool:
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == attr:
            if owner is None:
                return True
            v = f.value
            if isinstance(v, ast.Name) and v.id == owner:
                return True
            # self._js_hash_routes(...) -- attribute on self
            if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) \
                    and v.value.id == "self":
                return True
    return False


def test_EVERY_crawl_path_registers_hash_routes():
    """Phase 209's own first attempt is the reason this test exists.

    I wired `hash_route_urls` into the *static* crawl and left the default
    path (`_crawl_spa`, used whenever Playwright is installed) untouched --
    so every unit test on the static path stayed green while a real SPA scan
    registered 0 fragment endpoints.  A guard that only asks "does the file
    contain the call" cannot see that; the call has to be inside each crawl
    entry point by NAME.
    """
    src = _engine_source_files(SYNC_CRAWL)["scanner_crawl"]
    static = _function_body(src, "_crawl")
    spa = _function_body(src, "_crawl_spa")
    helper = _function_body(src, "_js_hash_routes")
    assert static and spa and helper, (
        "crawl entry points moved/renamed -- update this guard with a reason; "
        f"static={bool(static)} spa={bool(spa)} helper={bool(helper)}")
    assert (_calls_in(static, "hash_route_urls", "js_miner")
            or _calls_in(static, "_js_hash_routes")), \
        "the static crawl no longer registers fragment routes"
    assert _calls_in(spa, "_js_hash_routes"), \
        ("the SPA (default) crawl no longer registers fragment routes -- "
         "this is the exact path that was missing in the first attempt")
    assert _calls_in(helper, "hash_route_urls", "js_miner"), \
        "the shared helper no longer calls the miner"


def test_async_fragment_skip_uses_an_imported_urlparse():
    """`urlparse` is imported locally inside several async methods; a call
    site outside those scopes raises NameError at runtime, which the module
    import will not show."""
    from xssentinel.core import async_scanner as ASYNC
    assert hasattr(ASYNC, "urlparse"), (
        "async_scanner.urlparse missing: the fragment skip would NameError")
    src = open(os.path.join(ROOT, "xssentinel", "core", "async_scanner.py"),
               encoding="utf-8").read()
    assert "hash_route_urls" not in src, (
        "route discovery belongs in the crawl module; if it moved here, "
        "update this guard with a reason")
