"""Reproducible PoC generation for confirmed findings.

A finding is only useful if the tester can *reproduce* it.  For every confirmed
vulnerability we generate three ready-to-use artifacts:

  * ``curl``   - a copy-paste command that reproduces the request.
  * ``url``    - a ready GET URL with the payload in the parameter (GET only).
  * ``html``   - a self-contained HTML page that triggers the XSS when opened
                 in a browser (iframe / auto-submit form / location.hash for
                 DOM sources).  Hand this to a colleague or drop it on a host.

DOM findings store a *marker* (not a real exploit) as their payload, so we
substitute a canonical proof-of-execution payload (``alert(document.domain)``)
to make the PoC actually fire.
"""
from __future__ import annotations

import shlex
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, quote

# Canonical proof-of-execution payload used for DOM PoC pages (clearly shows
# code execution without doing anything destructive).
DOM_POC_PAYLOAD = "<img src=x onerror=alert(document.domain)>"

# Findings whose stored payload is just a taint marker, not a real exploit.
_MARKER_TYPES = ("dom", "dom_dynamic")

# Session headers that must NOT be copied into a curl PoC (Phase 98):
# transport-control hops curl manages itself, and Cookie has its own
# replay channel (-b).  Everything else -- Authorization, X-API-Key,
# X-CSRF-Token, custom anti-bot headers, the (stealth) User-Agent --
# is exactly what an authenticated API target needs to replay.
_POC_HEADER_BLOCKLIST = frozenset({
    "host", "content-length", "content-type", "connection",
    "accept", "accept-encoding", "cookie",
})


def _poc_headers(headers: dict | None) -> dict:
    """Filter session headers down to the replay-worthy set (lowercased
    names de-duped against the blocklist; original casing preserved)."""
    out: dict = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in _POC_HEADER_BLOCKLIST:
            continue
        if v is None:
            continue
        out[k] = str(v)
    return out


def _enc(s: str) -> str:
    return quote(s, safe="")


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def build_poc(finding, csrf_fields: dict | None = None,
              cookies: dict | None = None,
              headers: dict | None = None) -> dict:
    """Return a PoC dict for a Finding (or its .data dict).

    Phase 48: two optional replay-context extras:
      * ``csrf_fields`` -- the original request's OTHER form fields
        (hidden CSRF tokens etc.) besides the injected one.  POST PoCs then
        replay the full body so CSRF-protected endpoints actually accept
        the request instead of 403ing on a single-parameter body.
      * ``cookies`` -- session cookie dict.  When given, the curl PoC
        carries ``-b`` so authenticated findings replay against the same
        session.  Optional and OFF by default (reports may be shared).
    Phase 98: ``headers`` -- session headers to replay as ``-H`` args
    (Authorization / X-API-Key / custom anti-bot headers ...).  This is
    the last leg of the authenticated-replay gap: a JSON API guarded by
    a bearer token 401s any cookie-less curl PoC, and cookies alone
    cannot carry it.  Transport-control headers and Cookie (its own
    ``-b`` channel) are filtered out.  Same opt-in default as cookies.
    """
    d = finding.data if hasattr(finding, "data") else finding
    csrf_fields = dict(csrf_fields or {})
    if not csrf_fields:
        csrf_fields = dict(d.get("csrf_fields") or {})
    cookies = dict(cookies or {})
    replay_headers = _poc_headers(headers)
    url = d.get("url") or ""
    method = (d.get("method") or "GET").upper()
    param = d.get("param")
    ftype = d.get("type")
    payload = d.get("payload") or ""
    if ftype == "dom_sink_reachability":
        # Delivery-only DOM evidence has no observed execution.  Fabricating
        # an active exploit here would turn a low reachability hint into a
        # PoC that claims more than the browser measured.
        return {"curl": "", "url": "", "html": ""}
    if ftype in _MARKER_TYPES:
        poc_payload = DOM_POC_PAYLOAD
    else:
        poc_payload = payload

    poc: dict = {"curl": "", "url": "", "html": ""}
    if replay_headers:
        poc["replay_headers"] = dict(replay_headers)

    # --- request-level PoC (curl / ready URL) ---
    cookie_arg = ""
    if cookies:
        cookie_arg = " -b '" + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "'"
    hdr_args = "".join(f" -H '{k}: {v}'" for k, v in replay_headers.items())
    # Phase 85: non-query carriers (transport-layer findings) -- the
    # payload lives in a header / cookie / the URL path, never in a query
    # parameter.  A query-param PoC would replay against the wrong carrier
    # (report.py Phase 56 fixed the same asymmetry for the burp exporter).
    import re as _re
    hdr_m = _re.match(r"^\(header:([^)]+)\)$", param or "")
    ck_m = _re.match(r"^\(cookie:([^)]+)\)$", param or "")
    path_like = param in ("(path)", "(error_path)")
    if hdr_m or ck_m or path_like:
        if hdr_m:
            # Phase 178b: send the payload RAW.  The scanner put it on the
            # wire un-encoded (transport_layers: headers={header: payload})
            # and header_xss.build_poc_curl ships it literally too; the old
            # _enc() replayed a value that never existed on the wire, and a
            # raw-reflecting target echoed percent-encoding -- no
            # executable markup, no reproduction.  The CORS branch below
            # states the same principle for the same reason.  Shell safety
            # comes from shlex-quoting the whole -H argument, not from
            # mangling the value.
            hdr = f"{hdr_m.group(1)}: {poc_payload}"
        elif ck_m:
            # Cookie values DO ride the wire percent-encoded
            # (cookie_xss sends through _cookie_encode_value), so the
            # encoded replay matches what the scanner actually sent.
            hdr = f"Cookie: {ck_m.group(1)}={_enc(poc_payload)}"
        else:
            # path/error-path carriers already embed the payload in the
            # URL itself (transport_layers wrote it into the finding URL).
            hdr = ""
            url_poc = url
        if not path_like:
            url_poc = url
        poc["url"] = url_poc
        cookie_arg = ""
        poc["curl"] = (f"curl -i '{url_poc}'"
                       + (f" -H {shlex.quote(hdr)}" if hdr else "") + hdr_args)
        poc["html"] = (
            f"<html><body>\n<!-- Non-query carrier ({'header' if hdr_m else 'cookie' if ck_m else 'path'}): "
            f"replay with the curl command. -->\n"
            f"<pre>{_html_escape(poc['curl'])}</pre>\n</body></html>")
        return poc

    # Phase 164: honour the carrier the scanner recorded.  Inferring it from
    # the method ("POST -> body") is wrong for every position-shift finding:
    # scanner._try_position_shift re-fires the payload into the OTHER location
    # to slip past a WAF that guards only the original one, so the shipped
    # curl put the payload in the one place the WAF inspects.  Measured on
    # pos-pshift-01: the PoC replayed into "Sorry, you have been blocked",
    # while `-X POST '<url>?q=<payload>'` returns 200 and reflects.
    param_in = str(d.get("param_in") or "").lower()
    # Phase 213: a fragment-carried key (``q@hash`` from the DOM engine) is
    # NOT an HTTP carrier -- no request ever sees it, so the query branch
    # below would ship a curl replaying ``?q@hash=...`` at a server that can
    # never read it (dom findings ride method=GET, which is exactly the
    # branch's query-shape trigger).  The PoC is the HTML page navigating the
    # fragment; the curl states where the key actually lives.
    _frag = _re.fullmatch(r"([^@\s]+)@hash", param or "") \
        if ftype in _MARKER_TYPES and param else None
    if _frag:
        poc["curl"] = (f"# Payload rides the URL FRAGMENT key "
                       f"'{_frag.group(1)}' (never sent to the server); "
                       f"open the HTML PoC below "
                       f"(source: {d.get('context') or 'unknown'})")
    elif param:
        if param_in == "query" or method == "GET":
            p = urlparse(url)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            q[param] = poc_payload
            url_poc = urlunparse(p._replace(query=urlencode(q)))
            poc["url"] = url_poc
            if method == "GET":
                poc["curl"] = f"curl -i{cookie_arg}{hdr_args} '{url_poc}'"
            else:
                # POST whose payload rode the query: keep the method (the
                # endpoint may require it), send no body at all.
                poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} -X {method} "
                               f"'{url_poc}'")
        elif (ftype in ("upload_xss", "stored_upload")):
            # Multipart upload finding: the payload lives in the FILE NAME,
            # so the curl replay must send a real multipart part with that
            # filename (@/dev/null = empty file content, the server only cares
            # about the name).  A browser cannot preset a filename, so the
            # HTML PoC (below) is a note.
            fld = param.replace("[filename]", "")
            poc["curl"] = (
                f"curl -i{cookie_arg}{hdr_args} -X POST '{url}' "
                f"-F '{fld}=@/dev/null;filename={_enc(poc_payload)}'")
        else:  # POST / other, payload in the body
            # Full body: the CSRF/hidden fields the endpoint required +
            # the injected parameter.  urlencode makes it shell-safe
            # inside single quotes (no raw quotes survive).
            body = dict(csrf_fields)
            body[param] = poc_payload
            body_qs = urlencode(body)
            poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} -X {method} "
                           f"'{url}' --data '{body_qs}'")
    elif ftype == "cors_misconfig" and payload:
        # Phase 164: this finding has no injectable PARAMETER -- its carrier is
        # a request header -- so it fell into the "no parameter" branch and the
        # PoC was a placeholder ("no injectable parameter; open the HTML PoC
        # below") that reproduces nothing.  Measured on pos-cors-01: the
        # payload is the attacker Origin and the evidence already carries the
        # exact request, so ship that as the curl.
        poc["url"] = url
        # A HEADER value is not URL-encoded (the scanner sent it raw -- see
        # the finding's evidence), so percent-encoding it here would put a
        # mangled origin on the wire and a validating server would reject it.
        safe_origin = str(payload).replace("'", "")
        poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} '{url}' "
                       f"-H 'Origin: {safe_origin}'")
        poc["html"] = (
            f"<html><body>\n"
            f"<!-- CORS misconfiguration: the server echoes the attacker "
            f"Origin in Access-Control-Allow-Origin -->\n"
            f"<pre>{_html_escape(poc['curl'])}</pre>\n</body></html>")
        return poc
    else:
        # No parameter (pure DOM sink via hash/cookie): the PoC is the HTML page.
        poc["curl"] = (f"# No injectable parameter; open the HTML PoC below "
                       f"(source: {d.get('context') or 'unknown'})")

    # --- HTML PoC page ---
    poc["html"] = _html_poc(d, url, method, param, poc_payload, ftype,
                            csrf_fields)
    return poc


def _html_poc(d, url, method, param, payload, ftype,
              csrf_fields: dict | None = None) -> str:
    esc = _html_escape
    csrf_fields = dict(csrf_fields or {})
    if ftype in _MARKER_TYPES:
        # DOM XSS: navigate the page with the payload in the taint source
        # the scanner actually delivered through.  Phase 213: the finding's
        # param names that position -- ``q@hash`` = fragment-carried key
        # (only the page's router ever sees it, and the route path must
        # survive or the SPA renders a different view), a plain name = query
        # key.  With no param keep the legacy raw-source shapes.
        import re as _re
        _fm = _re.fullmatch(r"([^@\s]+)@hash", param) if param else None
        if _fm:
            from .dom_engine import _with_hash_param_value
            target = _with_hash_param_value(url, _fm.group(1), payload)
        elif param:
            from .dom_engine import _with_param_value
            target = _with_param_value(url, param, payload)
        elif "search" in (d.get("context") or "").lower():
            target = f"{url}?xssv_probe={_enc(payload)}"
        else:
            target = f"{url}#{_enc(payload)}"
        return (f'<html><body>\n'
                f'<!-- DOM-XSS PoC: navigates the vulnerable page with the '
                f'payload in the taint source -->\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    if str(d.get("param_in") or "").lower() == "query" and param:
        # Phase 164: the payload rode the QUERY (position-shift finding).  A
        # form would put it back in the body -- the one place the WAF guards,
        # which is why the shift exists.  Navigate with it in the URL instead.
        p = urlparse(url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        q[param] = payload
        target = urlunparse(p._replace(query=urlencode(q)))
        return (f'<html><body>\n'
                f'<!-- payload rides the QUERY (position shift): a form would '
                f'put it back in the body the WAF inspects -->\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    if ftype in ("upload_xss", "stored_upload"):
        # Browsers cannot preset a file input's filename, so the only
        # faithful reproduction of a filename-based upload XSS is the curl
        # multipart command (see build_poc).  The HTML page documents it.
        return ('<html><body>\n'
                '<!-- Upload-filename XSS cannot be reproduced by an HTML '
                'page: a browser always sends the local file name.\n'
                '     Use the curl PoC: multipart -F with the hostile '
                'filename. -->\n'
                '<p>Upload-filename XSS -- reproduce with the curl command '
                '(a browser cannot preset a filename).</p>\n'
                '</body></html>')
    if method == "POST" or ftype == "stored":
        # Auto-submit form reproduces a POST / stored injection.  Phase 48:
        # CSRF/hidden fields from the original request ride along as hidden
        # inputs -- without them CSRF-protected endpoints 403 the replay.
        hidden = ""
        for k, v in (csrf_fields or {}).items():
            hidden += (f'  <input type="hidden" name="{esc(k)}" '
                       f'value="{esc(v)}">\n')
        return (f'<html><body>\n'
                f'<form id="poc" action="{esc(url)}" method="{method}">\n'
                f'{hidden}'
                f'  <input name="{esc(param)}" value="{esc(payload)}">\n'
                f'</form>\n'
                f'<script>document.getElementById("poc").submit();</script>\n'
                f'</body></html>')
    if param:
        # Reflected GET: open the page with the payload in the URL.
        target = f"{url}?{param}={_enc(payload)}"
        return (f'<html><body>\n'
                f'<iframe src="{esc(target)}" '
                f'onload="window.location.href=\'{esc(target)}\'"></iframe>\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    return ('<html><body>\n<!-- no parameter; see curl above -->\n'
            '</body></html>')


# ---------------------------------------------------------------------------
# Phase 14a: Interactive HTML PoC generator
# ---------------------------------------------------------------------------
