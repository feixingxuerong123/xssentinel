"""Phase 122: WAF block-page hints must be a BODY signal.

Regression for a benchmark-found defect: detect() searched full_blob
(headers + body) for _BLOCK_BODY_HINTS, whose patterns include the
cloudflare/cf-ray FINGERPRINTS -- so every unblocked 200 response from
any fingerprinted WAF was classified as blocked, and _try_payload then
discarded every payload the WAF actually let through.  That silently
killed payload confirmation on ALL WAF'd sites (L2_position_shift was
just the first benchmark case to walk this path).
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xssentinel.core import waf as wafmod  # noqa: E402


class _R:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


_WAF_HEADERS = {"Server": "cloudflare", "CF-RAY": "7c1f2e3a-SJC"}


class TestBlockHintsAreBodySignals(unittest.TestCase):

    def test_unblocked_200_from_fingerprinted_waf_is_not_blocked(self):
        """The exact defect: WAF fingerprint headers + a normal page
        carrying a REFLECTED PAYLOAD must not read as a block."""
        r = _R(200, dict(_WAF_HEADERS),
               '<div id="search">Results for '
               '<img src=x onerror=alert("xssv_abcd1234")></div>')
        d = wafmod.detect(r)
        self.assertEqual(d["waf"], "Cloudflare")
        self.assertFalse(d["blocked"])
        self.assertEqual(d["reason"], "")

    def test_real_block_page_in_body_is_blocked(self):
        r = _R(200, dict(_WAF_HEADERS),
               "<h1>Attention Required</h1><p> Sorry, you have been "
               "blocked. Ray ID: 7c1f2e3a</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertIn("block page", d["reason"])

    def test_strong_status_blocks_regardless_of_body(self):
        r = _R(406, dict(_WAF_HEADERS), "<p>ok</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["reason"], "HTTP 406")

    def test_soft_block_status_needs_vendor(self):
        r = _R(404, {"Server": "nginx"}, "<p>nope</p>")
        d = wafmod.detect(r)
        self.assertFalse(d["blocked"])

    def test_body_hint_without_vendor_is_generic_block(self):
        r = _R(200, {"Server": "nginx"}, "<p>Request blocked by policy</p>")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["waf"], "Generic/Unknown WAF")

    def test_fingerprint_headers_alone_do_not_invent_a_block(self):
        """A WAF-fingerprinted EMPTY page is still not a block page."""
        r = _R(200, dict(_WAF_HEADERS), "<p>hello</p>")
        d = wafmod.detect(r)
        self.assertFalse(d["blocked"])


class TestFingerprintSpecificity(unittest.TestCase):
    """Phase 291: body fingerprints must not fire on ordinary front-end text.

    Measured on OWASP Juice Shop 20.2.0 (no WAF): its Angular/Material CSS
    contains ``--mat-sys-on-surface-variant`` and the page carries class
    names like ``interface-header`` / ``space-around``.  The old Cisco ACE
    rule matched ``ace-`` inside those words, and the old F5 rule matched
    the bare token ``tsa`` inside ``const tsa = ...``.  Either hit makes
    the scanner generate WAF-evasion variants a clean target never needs
    and tells the operator they are behind a WAF that is not there.
    """

    def test_css_custom_properties_are_not_cisco_ace(self):
        r = _R(200, {"Server": "x"},
               "<style>--mat-sys-on-surface-variant:#e0e2ec</style>")
        self.assertIsNone(wafmod.detect(r)["waf"])

    def test_hyphenated_class_names_are_not_cisco_ace(self):
        r = _R(200, {"Server": "x"},
               '<div class="interface-header space-around">')
        self.assertIsNone(wafmod.detect(r)["waf"])

    def test_js_identifier_tsa_is_not_f5(self):
        r = _R(200, {"Server": "x"},
               "const tsa = computeTsA(x); let bitsa = 1;")
        self.assertIsNone(wafmod.detect(r)["waf"])

    def test_real_ace_cookie_still_fingerprints(self):
        r = _R(200, {"Set-Cookie": "ACE-abc=1"}, "<html>ok</html>")
        self.assertEqual(wafmod.detect(r)["waf"], "Cisco ACE")

    def test_real_f5_cookies_still_fingerprint(self):
        for cookie in ("BIGipServerpool_80=xyz", "TS01a1b2c3=abc"):
            r = _R(200, {"Set-Cookie": cookie}, "<html>ok</html>")
            self.assertEqual(wafmod.detect(r)["waf"], "F5 BIG-IP ASM", cookie)

    def test_vendor_name_in_body_still_fingerprints(self):
        r = _R(200, {"Server": "x"}, "Blocked by Cisco security")
        self.assertEqual(wafmod.detect(r)["waf"], "Cisco ACE")


class TestBlockEvidencePrecision(unittest.TestCase):
    """Phase 294: "blocked" must mean "this request was refused".

    The old hint list carried vendor names and topic words, so it fired on
    ordinary content.  Measured false positives that each DISCARD the
    payloads the target actually let through (the Phase 122 silent-FN
    family):

      * every Cloudflare-fronted site's allowed 200 response -- Cloudflare
        injects a Ray-ID comment, and "cloudflare" was a hint;
      * a JS variable named ``waf``, the word "wafer", a marketing page
        about firewalls, a support page mentioning "request ID", a
        security dashboard reading "malicious requests blocked";
      * a Chinese security article containing 攻击 / 防火墙 / 安全策略.

    And the status path counted 401/404/400/500/502 as blocked whenever a
    vendor header was present, i.e. every missing or auth-gated endpoint
    behind a CDN.

    Refusal PHRASES still block; vendor NAMES no longer do.
    """

    CF = {"Server": "cloudflare", "CF-RAY": "7c1f2e3a4b5c6d7e-SJC"}

    def test_allowed_200_behind_cloudflare_is_not_blocked(self):
        # the benchmark's own allowed-waf shape, and every real CF site
        r = _R(200, dict(self.CF),
               "<!-- Cloudflare Ray ID: 7c1f2e3a --><div>apple</div>")
        d = wafmod.detect(r)
        self.assertEqual(d["waf"], "Cloudflare")
        self.assertFalse(d["blocked"])

    def test_missing_or_auth_gated_behind_cdn_is_not_blocked(self):
        for status in (404, 401, 400, 500, 502):
            r = _R(status, dict(self.CF), "nope")
            self.assertFalse(wafmod.detect(r)["blocked"],
                             f"HTTP {status} + vendor header must not block")

    def test_topic_words_are_not_block_evidence(self):
        for body in ("const wafEnabled = false;",
                     '<div class="waf-banner">',
                     "Our wafer products",
                     "<h1>What is a WAF?</h1>",
                     "Request ID: 8f3a-22c1",
                     "Include your request ID when contacting support.",
                     "Next-gen firewall appliances",
                     "malicious requests blocked this week: 12",
                     "Our security policy covers cookies."):
            self.assertFalse(wafmod.detect(_R(200, {"Server": "x"}, body))["blocked"],
                             body)

    def test_chinese_topic_words_are_not_block_evidence(self):
        # 攻击 / 防火墙 appear in any security article; only refusals count.
        self.assertFalse(wafmod.detect(
            _R(200, {"Server": "x"}, "常见攻击面与防火墙配置"))["blocked"])

    def test_refusal_phrases_still_block(self):
        for body in ("Request blocked by policy", "Access Denied",
                     "访问被拒绝", "you have been blocked"):
            d = wafmod.detect(_R(200, {"Server": "x"}, body))
            self.assertTrue(d["blocked"], body)
            self.assertEqual(d["waf"], "Generic/Unknown WAF")

    def test_vendor_block_page_still_blocks_via_status(self):
        r = _R(403, dict(self.CF),
               "Attention Required! Sorry, you have been blocked")
        d = wafmod.detect(r)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["waf"], "Cloudflare")


if __name__ == "__main__":
    unittest.main()
