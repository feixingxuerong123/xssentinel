"""Phase 330: the bare ``ecd`` Edgecast rule fired on ordinary text.

Measured on the pre-fix tree (dev/_p330_waf_edgecast_probe.py):

  * the scanner's own 8-hex marker tokens contain "ecd" 7/5000 = 0.14% of
    the time -- one reflected response is enough to make the scan report
    "WAF detected: Edgecast" and switch the payload ladder;
  * ordinary crypto bundles say ECDSA / ECDH;
  * a marker reflected into a response HEADER matched the header pass at
    high confidence (``ecd`` in a Location: URL);
  * meanwhile the real Edgecast fingerprints ``Server: ECS (dca/...)``,
    ``Server: ECAcc (...)`` and ``X-EC-*`` were never detected.

The fix keeps the unique word as a body fingerprint and moves ECD/ECS/ECAcc
into their parenthesised Server form, header-only, plus the X-EC-* CDN
headers.  This file pins both directions and carries a mutation control so
the false-positive assertions cannot pass on the old rule.
"""
from __future__ import annotations

import random
import re
import unittest

import xssentinel.core.waf as wafmod

#: The pre-Phase-330 Edgecast rule, verbatim, for the mutation control.
_OLD_EDGECAST = re.compile(r"edgecast|ecd", re.I)


class _R:
    def __init__(self, status, headers, text):
        self.status_code = status
        self.headers = headers
        self.text = text


def detect(body="", headers=None, status=200):
    return wafmod.detect(_R(status, headers or {"Server": "nginx"}, body))


def _marker_tokens(n=2000, seed=330):
    rng = random.Random(seed)
    return ["xssentinel_dom_%08x" % rng.getrandbits(32) for _ in range(n)]


class TestFalsePositiveFamily(unittest.TestCase):
    """Shapes that must NOT identify a WAF (pre-fix they all said Edgecast)."""

    def test_marker_token_containing_ecd_in_body(self):
        d = detect(body='<div id="out">xssentinel_dom_abecd123</div>')
        self.assertIsNone(d["waf"])

    def test_marker_token_reflected_into_a_response_header(self):
        # Pre-fix this was ``high`` confidence: the header pass ran the same
        # body-shaped rule over every header value.
        d = detect(headers={"Server": "nginx",
                            "Location": "/next?t=xssentinel_dom_abecd123"})
        self.assertIsNone(d["waf"])

    def test_crypto_identifiers_in_a_bundle(self):
        body = ("<script>const alg='ECDSA';"
                "crypto.subtle.importKey('ECDH');</script>")
        d = detect(body=body)
        self.assertIsNone(d["waf"])

    def test_ecs_as_a_product_name_is_not_edgecast(self):
        # AWS ECS, not Edgecast: the Server-form anchor requires "(".
        d = detect(body="<p>Our ECS cluster runs in us-east-1.</p>")
        self.assertIsNone(d["waf"])

    def test_eddsa_prose_does_not_match(self):
        self.assertIsNone(detect(body="<p>EdDSA and ECDSA signatures</p>")["waf"])


class TestRealFingerprints(unittest.TestCase):
    """Real Edgecast signals must keep matching -- three of them are new."""

    def test_server_ec_d_with_datacenter(self):
        d = detect(headers={"Server": "ECD (dca/1234)"})
        self.assertEqual(d["waf"], "Edgecast")
        self.assertEqual(d["confidence"], "high")

    def test_server_ecs_with_datacenter(self):
        d = detect(headers={"Server": "ECS (dca/24B4)"})
        self.assertEqual(d["waf"], "Edgecast")

    def test_server_ecacc_with_datacenter(self):
        d = detect(headers={"Server": "ECAcc (dca/24B4)"})
        self.assertEqual(d["waf"], "Edgecast")

    def test_x_ec_cdn_headers(self):
        for hdr in ("X-EC-Cache", "X-EC-Debug", "X-EC-Source-Zone"):
            d = detect(headers={"Server": "nginx", hdr: "x"})
            self.assertEqual(d["waf"], "Edgecast", hdr)

    def test_vendor_word_in_body_is_a_medium_fingerprint(self):
        d = detect(body="<footer>Powered by Edgecast</footer>")
        self.assertEqual(d["waf"], "Edgecast")
        self.assertEqual(d["confidence"], "medium")

    def test_fingerprints_alone_never_mean_blocked(self):
        for hdrs in ({"Server": "ECD (dca/1234)"},
                     {"X-EC-Cache": "HIT"}):
            self.assertFalse(detect(headers=hdrs)["blocked"])


class TestMarkerTokenSilence(unittest.TestCase):
    """The general invariant: no rule may fire on the scanner's own tokens."""

    def test_random_marker_tokens_never_fingerprint_a_vendor(self):
        tokens = _marker_tokens()
        hits = [t for t in tokens if detect(body=f"<span>{t}</span>")["waf"]]
        self.assertEqual(hits, [])

    def test_token_in_header_never_fingerprints_a_vendor(self):
        for tok in _marker_tokens(500, seed=331):
            d = detect(headers={"Server": "nginx", "Location": f"/x?t={tok}"})
            self.assertIsNone(d["waf"], tok)

    def test_quick_helper_agrees(self):
        self.assertIsNone(wafmod.is_waf_signature("xssentinel_dom_abecd123"))
        self.assertEqual(wafmod.is_waf_signature("Powered by Edgecast"),
                         "Edgecast")


class TestMutationControl(unittest.TestCase):
    """Prove the false-positive tests would have failed on the old rule."""

    def test_old_rule_matched_the_false_positive_samples(self):
        samples = [
            "xssentinel_dom_abecd123",
            "const alg = 'ECDSA'",
            "/next?t=xssentinel_dom_abecd123",
            "EdDSA and ECDSA signatures",
        ]
        for s in samples:
            self.assertIsNotNone(_OLD_EDGECAST.search(s), s)

    def test_old_rule_hit_the_random_token_set(self):
        tokens = _marker_tokens()
        hits = [t for t in tokens if _OLD_EDGECAST.search(t)]
        self.assertGreater(len(hits), 0,
                           "token set must exercise the old rule")
        # ... and the current rule must not: that is the regression.
        self.assertEqual([t for t in tokens if detect(body=t)["waf"]], [])

    def test_new_rule_keeps_every_real_fingerprint(self):
        rules = [(rx, kind) for name, rx, kind in wafmod._WAF_SIGNATURES
                 if name == "Edgecast"]
        body_rules = [rx for rx, kind in rules if kind == "any"]
        header_rules = [rx for rx, kind in rules if kind == "header"]
        self.assertTrue(body_rules, "body-visible vendor word must remain")
        self.assertTrue(header_rules, "header-only CDN fingerprints must exist")
        self.assertIsNotNone(body_rules[0].search("Powered by Edgecast"))
        self.assertIsNotNone(header_rules[0].search("Server: ECS (dca/24B4)"))
        self.assertIsNotNone(header_rules[0].search("X-EC-Cache: HIT"))


class TestAsyncRawPath(unittest.TestCase):
    def test_detect_from_raw_matches_detect(self):
        fp = wafmod.detect_from_raw(
            200, {"Location": "/x?t=xssentinel_dom_abecd123"}, "")
        self.assertIsNone(fp["waf"])
        real = wafmod.detect_from_raw(200, {"Server": "ECS (dca/24B4)"}, "")
        self.assertEqual(real["waf"], "Edgecast")


if __name__ == "__main__":
    unittest.main()
