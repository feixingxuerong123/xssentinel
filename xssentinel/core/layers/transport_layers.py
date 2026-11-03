"""Transport-injection advanced layers: header, URL path, cookie, error
page.  (Phase 39 split: moved verbatim from advanced_layers.py.)"""
from __future__ import annotations

import os
import secrets

from .. import header_xss as header_mod
from .. import path_xss as path_mod
from .. import cookie_xss as cookie_mod
from .. import error_xss as error_mod

from .common import _make_finding
from ..stealth import marker as _stem_marker


def _adaptive_layers() -> bool:
    """Phase 353 A/B switch for the transport-layer evidence gates."""
    return (os.environ.get("XSS_ADAPTIVE_LAYERS", "1") != "0"
            and os.environ.get("XSS_BUDGET_V2", "1") != "0")


def _skip_layer(scanner, url, layer_id, method, reason):
    scanner.coverage.record_layer(url, layer_id, method, status="skipped",
                                  detail=reason)


def _header_probe_names(scanner, req) -> list[str]:
    """Injectable headers, minus Cookie when a session cookie is in play.

    The Phase 355 all-header canary sends every name in one request.  Sending
    ``Cookie: <canary>`` on an authenticated target replaces the operator's
    session cookie and turns every response into 401 -- measured on the
    self-hosted lab (/header: canary passed no token, header layer skipped,
    while a manual User-Agent reflection worked).  Cookie XSS has its own
    layer; the header layer must not destroy the session it is auditing.
    """
    names = list(header_mod.INJECTABLE_HEADERS)
    try:
        has_cookies = bool(getattr(getattr(req, "session", None), "cookies", None))
    except Exception:
        has_cookies = False
    if has_cookies and "Cookie" in names:
        names.remove("Cookie")
    return names


def _scan_header_xss(scanner, req, url: str) -> None:
    """Inject payloads via HTTP headers (User-Agent, Referer, XFF, ...)."""
    # Phase 20-3: record L8 header XSS layer.
    scanner.coverage.touch_layer(url, "L8_header", "GET",
                                 detail="probe injectable headers")
    probe_headers = _header_probe_names(scanner, req)
    try:
        # Phase 355 evidence canary (supersedes the Phase 353 3-header
        # prescreen): ONE request carrying EVERY declared header, each with
        # its own plain token.  Skip only when NO token reflects -- a
        # sample-of-N canary (N < len(list)) is unsound against selective
        # echo servers: tests/test_redteam_independent.py's /api/reflect
        # echoes ONLY Referer (declared entry 7) and the 3-canary prescreen
        # turned that confirmed finding into a false negative.  Plain tokens
        # (no payload markup) keep the canary off WAF payload rules; the
        # answer it buys is "does this app echo request headers at all".
        if _adaptive_layers():
            from urllib.parse import unquote as _uq
            canary_tokens = []
            canary_headers = {}
            for h in probe_headers:
                ptok = "xsshd_" + secrets.token_hex(4)
                canary_tokens.append(ptok)
                canary_headers[h] = ptok
            try:
                presp = req.get(url, headers=canary_headers)
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
                ptxt = presp.text or ""
            except Exception:
                ptxt = ""
            reflected = any(t in ptxt or t in _uq(ptxt)
                            for t in canary_tokens)
            if not reflected:
                _skip_layer(scanner, url, "L8_header", "GET",
                            "no header reflection in all-header canary")
                return
        # Phase 171: probe the WHOLE declared list.  The former
        # ``INJECTABLE_HEADERS[:6]`` was the *only* break point on Juice
        # Shop's HTTP-Header XSS challenge -- build/routes/saveLoginIp.js:55
        # reads ``req.headers['true-client-ip']``, which is entry SEVEN, so
        # that header was never sent and a hand-confirmed real finding was
        # unreachable (Phase 170c measured 39 requests / 0 findings there).
        #
        # The cost is bounded by the ``break`` below: the loop stops at the
        # first confirmed header, so only endpoints that reflect NONE of the
        # headers pay for all of them.  Measured when this landed (186 cases):
        # 12694 -> 15244 requests (+20.1%), verdicts unchanged.  At that time
        # it was an UPPER bound -- no case confirmed a header, so none of them
        # got the early-exit discount; Phase 172 added one that does
        # (pos-hdr-01: TP in 42 requests via the 7th header, against 53 for its
        # safe twin), so the ledger now measures both sides.  A real target
        # that reflects a header costs +2 (Juice Shop's saveLoginIp).
        from .. import verifier
        for header in probe_headers:
            token = "xsshd_" + secrets.token_hex(3)
            # Marker-form fan-out: addslashes rewrites alert('tok') into a JS
            # syntax error while alert(tok)/alert("tok")/alert(`tok`) still
            # run, so the same injection point is probed once per quoting
            # shape, capped by stamp_forms' budget.  The first shape follows
            # the template's own style (unquoted numeric).
            forms = verifier.stamp_forms_or_legacy("<svg/onload=alert(1)>",
                                                   token, 4)
            hit = False
            for _form, eff, payload in forms:
                try:
                    # Most requester implementations accept headers kwarg.
                    resp = req.get(url, headers={header: payload})
                    scanner._bump()
                    scanner.coverage.record_request(url, "GET")
                except Exception:
                    continue
                text = resp.text or ""
                result = header_mod.analyze_response(text, header, eff)
                if not result["reflected"]:
                    continue
                # Confirm the payload is in an executable context (not just
                # the token echoed as escaped text).
                v = verifier.verify_semantic(
                    text, eff, response_headers=dict(resp.headers))
                if not v["confirmed"]:
                    continue
                curl_poc = header_mod.build_poc_curl(url, header, payload)
                html_poc = header_mod.build_poc_html(url, header, payload)
                scanner._add(_make_finding(
                    url=url, method="GET", param=f"(header:{header})",
                    payload=payload,
                    context=result.get("context_hint", "html_element"),
                    severity="high",
                    ftype="header_xss",
                    evidence=(
                        f"payload reflected from {header} header: {v['detail']}"
                    ),
                    poc_curl=curl_poc,
                    poc_html=html_poc,
                    header=header,
                ))
                scanner.coverage.record_finding(url, "GET")
                if scanner.verbose:
                    print(f"    [+] Header XSS via {header}")
                hit = True
                break  # one marker shape per header is enough
            if hit:
                break  # one header finding per URL is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] header layer error: {e}")


def _scan_path_xss(scanner, req, url: str) -> None:
    """Inject payloads via URL path segments."""
    # Phase 20-3: record L8 path XSS layer.
    scanner.coverage.touch_layer(url, "L8_path", "GET",
                                 detail="probe URL path segment")
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.path or parsed.path == "/":
            return  # nothing to inject into
        token = "xspath_" + secrets.token_hex(3)
        # Phase 109: use the module's PATH-SAFE payloads and its URL
        # builder.  The previous inline payload was
        # "<svg/onload=alert('token')>" -- it contains a SLASH, and it was
        # concatenated into the path raw, so it arrived as TWO segments
        # ("<svg" + "onload=...") and no target that echoes a single
        # segment could ever reflect it.  build_test_url() percent-encodes
        # with safe="" (so "/" becomes %2F) exactly like a browser.
        segment = parsed.path.rstrip("/").rsplit("/", 1)[-1] or "x"
        last_url = None
        last_text = ""
        last_resp = None
        # Phase 353: one bare-marker path answers "does this router echo the
        # path segment at all?"  No reflection -> the 13 payload shapes
        # cannot confirm either.
        if _adaptive_layers():
            from urllib.parse import unquote
            probe_url = path_mod.build_test_url(url, segment, "xssentinel")
            if probe_url:
                try:
                    presp = req.get(probe_url)
                    scanner._bump()
                    scanner.coverage.record_request(url, "GET")
                    ptxt = presp.text or ""
                except Exception:
                    ptxt = ""
                if "xssentinel" not in ptxt and \
                        "xssentinel" not in unquote(ptxt):
                    _skip_layer(scanner, url, "L8_path", "GET",
                                "path segment not reflected by bare marker")
                    return
        for tmpl in path_mod.path_payloads():
            if tmpl == "xssentinel":
                continue  # bare marker: reflection-only, cannot fire
            payload = tmpl.replace("alert(1)", f"alert('{token}')")
            if token not in payload:
                payload = payload + token
            test_url = path_mod.build_test_url(url, segment, payload)
            if not test_url:
                continue
            try:
                resp = req.get(test_url)
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            last_url, last_text, last_resp = test_url, text, resp
            if not path_mod.analyze_response(text, token)["reflected"]:
                continue
            from .. import verifier
            v = verifier.verify_semantic(text, token,
                                         response_headers=dict(resp.headers))
            if v["confirmed"]:
                break
        else:
            return
        if last_resp is None or token not in (last_text or ""):
            return
        result = path_mod.analyze_response(last_text, token)
        test_url = last_url
        text = last_text
        resp = last_resp
        from .. import verifier
        v = verifier.verify_semantic(text, token,
                                     response_headers=dict(resp.headers))
        if not v["confirmed"]:
            return
        curl_poc = path_mod.build_poc_curl(test_url)
        link_poc = path_mod.build_poc_link(test_url)
        scanner._add(_make_finding(
            url=test_url, method="GET", param="(path)",
            payload=payload,
            context=result.get("context", "html_element"),
            severity="high",
            ftype="path_xss",
            evidence=f"path segment reflected: {v['detail']}",
            poc_curl=curl_poc,
            poc_html=link_poc,
        ))
        scanner.coverage.record_finding(url, "GET")
        if scanner.verbose:
            print("    [+] Path XSS via URL segment")
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] path layer error: {e}")


def _scan_cookie_xss(scanner, req, url: str) -> None:
    """Inject payloads via cookie values."""
    # Phase 20-3: record L8 cookie XSS layer.
    scanner.coverage.touch_layer(url, "L8_cookie", "GET",
                                 detail="probe injectable cookies")
    try:
        # Phase 355 evidence canary (supersedes the Phase 353 2-cookie
        # prescreen), same soundness argument as the header canary: ONE
        # request carrying every candidate name the probe loop would pay
        # for ([:5]), each with its own plain token.  A 2-of-5 sample is
        # unsound against a server that reads only the third name; this
        # skip fires only when NO probeable name reflects.
        if _adaptive_layers():
            from urllib.parse import unquote
            canary_names = cookie_mod.candidate_cookies()[:5]
            canary_tokens = ["xsck_" + secrets.token_hex(4)
                             for _ in canary_names]
            canary_cookie = "; ".join(
                f"{n}={t}" for n, t in zip(canary_names, canary_tokens))
            try:
                presp = req.get(url, headers={"Cookie": canary_cookie})
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
                ptext = presp.text or ""
            except Exception:
                ptext = ""
            reflected = any(t in ptext or t in unquote(ptext)
                            for t in canary_tokens)
            if not reflected:
                _skip_layer(scanner, url, "L8_cookie", "GET",
                            "no cookie reflection in all-name canary")
                return
        for cookie_name in cookie_mod.candidate_cookies()[:5]:  # top 5 cookies
            token = "xsck_" + secrets.token_hex(3)
            marker_payload = f"<svg/onload=alert('{token}')>"
            try:
                resp = req.get(url, headers={"Cookie": f"{cookie_name}={marker_payload}"})
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            result = cookie_mod.analyze_response(text, token)
            if not result["reflected"]:
                continue
            # Phase 178c: a reflected cookie name earns the FULL payload
            # list, not the single svg shape.  Cookie values routinely
            # land inside JS strings (theme/lang/ui prefs), where markup
            # shapes are inert -- the sandbox correctly calls the mangled
            # block a syntax error -- and the one shape that works there
            # (`';alert(TOK);//`) was never sent.  Range3 /mypage:
            # reflected on every probe, 0 findings.
            from .. import verifier as _verifier
            for shape in cookie_mod.cookie_payloads():
                if "alert(1)" not in shape:
                    continue
                payload = shape.replace("alert(1)", f"alert('{token}')")
                try:
                    resp = req.get(url, headers={"Cookie": f"{cookie_name}={payload}"})
                    scanner._bump()
                    scanner.coverage.record_request(url, "GET")
                except Exception:
                    continue
                text = resp.text or ""
                if token not in text:
                    continue
                v = _verifier.verify_semantic(
                    text, token, response_headers=dict(resp.headers))
                if not v["confirmed"]:
                    continue
                curl_poc = cookie_mod.build_poc_curl(url, cookie_name, payload)
                html_poc = cookie_mod.build_poc_html(url, cookie_name, payload)
                scanner._add(_make_finding(
                    url=url, method="GET", param=f"(cookie:{cookie_name})",
                    payload=payload,
                    context=v.get("context") or result.get("context", "html_element"),
                    severity="high",
                    ftype="cookie_xss",
                    evidence=(
                        f"payload reflected from cookie {cookie_name}: {v['detail']}"
                    ),
                    poc_curl=curl_poc,
                    poc_html=html_poc,
                    cookie=cookie_name,
                ))
                scanner.coverage.record_finding(url, "GET")
                if scanner.verbose:
                    print(f"    [+] Cookie XSS via {cookie_name}")
                break
            else:
                continue
            break  # one cookie finding per URL is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] cookie layer error: {e}")


def _scan_error_xss(scanner, req, url: str) -> None:
    """Inject payloads to trigger error pages (404/500) that reflect input."""
    # Phase 20-3: record L8 error page XSS layer.
    scanner.coverage.touch_layer(url, "L8_error_page", "GET",
                                 detail="probe error-page reflection")
    try:
        # One error-page finding per host is enough -- the error page is
        # the same regardless of which endpoint triggered the 404 probe.
        # Phase 217: ATOMIC host claim, not a scan of scanner.findings.
        # The old check-then-emit raced on the append happening after the
        # check: an instant _add kept the window microscopic, but the
        # Phase 217 headless-confirmation mirror runs a ~1-2s browser
        # replay INSIDE _add -- measured, same tree, same target: the
        # widened window let concurrent endpoint scans emit 3 per-host
        # findings where the pre-mirror tree stably emitted 1.  The claim
        # also makes the contract monotone: one attempt per host, no
        # retry-via-another-endpoint after a failed probe (the 404 handler
        # is host-global, so a retry could only repeat the same answer).
        from urllib.parse import urlparse
        host_key = urlparse(url).netloc
        claimed = getattr(scanner, "_error_page_hosts", None)
        if claimed is None:
            claimed = set()
            scanner._error_page_hosts = claimed
        with scanner._lock:
            if host_key in claimed:
                return
            claimed.add(host_key)

        token = _stem_marker("xserr_") + secrets.token_hex(3)
        payload = f"<svg/onload=alert('{token}')>"
        from urllib.parse import urlunparse, quote
        parsed = urlparse(url)
        # Probe TWO error-page vectors:
        #   1. Append to the existing path (catches apps whose router
        #      falls through to a 404 handler for unknown sub-paths).
        #   2. A root-level non-existent path (catches apps whose router
        #      matches known path prefixes like /echo and returns 200 for
        #      /echo/<anything> -- the root probe avoids that false match).
        err_paths = [
            parsed.path.rstrip("/") + "/" + quote(payload, safe=""),
            "/__xssentinel_err__/" + quote(payload, safe=""),
        ]
        for err_path in err_paths:
            err_url = urlunparse((parsed.scheme, parsed.netloc, err_path,
                                  parsed.params, parsed.query, ""))
            try:
                resp = req.get(err_url)
                scanner._bump()
                scanner.coverage.record_request(url, "GET")
            except Exception:
                continue
            text = resp.text or ""
            result = error_mod.analyze_response(text, token,
                                                status_code=getattr(resp, "status_code", None))
            if not result["reflected"] or not result.get("is_error_page"):
                continue
            from .. import verifier
            v = verifier.verify_semantic(text, token,
                                         response_headers=dict(resp.headers))
            if not v["confirmed"]:
                continue
            curl_poc = error_mod.build_poc_curl(err_url)
            link_poc = error_mod.build_poc_link(err_url)
            scanner._add(_make_finding(
                url=err_url, method="GET", param="(error_path)",
                payload=payload,
                context=result.get("context", "html_element"),
                severity="high",
                ftype="error_page_xss",
                evidence=(
                    f"error page ({getattr(resp, 'status_code', '?')}) "
                    f"reflects payload: {v['detail']}"
                ),
                poc_curl=curl_poc,
                poc_html=link_poc,
                status_code=getattr(resp, "status_code", None),
            ))
            scanner.coverage.record_finding(url, "GET")
            if scanner.verbose:
                print(f"    [+] Error page XSS ({getattr(resp, 'status_code', '?')})")
            break  # one error-page finding per host is enough
    except Exception as e:
        if scanner.verbose:
            print(f"    [!] error layer error: {e}")


# =============================================================================
# Parameter-level layers
# =============================================================================

