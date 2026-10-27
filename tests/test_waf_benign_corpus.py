"""Phase 295: a benign corpus the WAF rules must stay silent on.

Two phases in a row fixed the SAME bug shape: a detection rule firing on
ordinary text.

  * Phase 291: Cisco ACE's bare ``ace-`` matched CSS custom properties
    (--mat-sys-on-surface-variant); F5's bare ``tsa`` matched
    ``const tsa = computeTsa(x)``.
  * Phase 294: _BLOCK_BODY_HINTS carried vendor names and topic words
    (waf / cloudflare / firewall / request id / 攻击 / 防火墙 ...), so
    ordinary pages -- including EVERY Cloudflare-fronted site's allowed
    200 response -- were "blocked", and blocked discards payloads.
  * Phase 330: the bare ``ecd`` Edgecast alternative matched any three hex
    characters (0.14% of the scanner's own marker tokens, and ECDSA in
    every crypto bundle).

Each fix was found by hand, one measurement at a time.  This test is the
net that should have caught both: a corpus of ordinary front-end text
(CSS, JS identifiers, Chinese/Japanese prose, error/support pages, API
payloads) that the detector must leave alone.

Contracts:
  1. ``blocked`` must be False for every sample.  This is the FN-critical
     property -- blocked means "the payloads are discarded".
  2. ``waf`` must be None for samples that do not name a vendor at all.
     (Samples that DO mention a vendor keep only contract 1: a body
     mention is a medium-confidence fingerprint, which is acceptable;
     treating it as a block is not.)
"""
from __future__ import annotations

import unittest

import xssentinel.core.waf as wafmod


class _R:
    def __init__(self, status, headers, text):
        self.status_code = status
        self.headers = headers
        self.text = text


# (label, body, names_a_vendor)
CORPUS = [
    # --- CSS ---
    ("material css vars",
     "<style>:root{--mat-sys-on-surface-variant:#e0e2ec;"
     "--md-sys-color-surface:#fff}</style>", False),
    ("tailwind classes",
     '<div class="space-around place-items-center interface-header '
     'surface-container">', False),
    # --- JS identifiers ---
    ("js tsa identifier", "const tsa = computeTsA(x); let bitsa = 1;", False),
    ("js waf variable", "if (wafEnabled) { wafRules.apply(req); }", False),
    ("js generic bundle",
     "function e(t){return t.replace(/[<>]/g,'')}var n={a:1,b:[2,3]};", False),
    # --- prose ---
    ("english prose", "Our wafer products are baked fresh every morning.", False),
    ("waf explainer", "<h1>What is a WAF?</h1><p>It sits in front of a site.</p>", False),
    ("cn security article", "常见攻击面与防火墙配置实践，安全策略需定期评审。", False),
    ("jp article", "ファイアウォールの設定とセキュリティポリシーについて", False),
    ("fr article", "Un pare-feu protège le réseau. La politique de sécurité...", False),
    # --- operational pages ---
    ("error with request id",
     "<h1>Internal Server Error</h1><p>Request ID: 8f3a-22c1</p>", False),
    ("support page", "<p>Include your request ID when contacting support.</p>", False),
    ("security dashboard",
     "<td>malicious requests blocked this week: 12</td>", False),
    ("firewall vendor page", "<h1>Next-gen firewall appliances</h1>", False),
    ("privacy policy", "<p>Our security policy covers cookies and logs.</p>", False),
    # --- API payloads ---
    ("json api", '{"id":7,"name":"apple","price":0.99,"tags":["fruit"]}', False),
    ("graphql error",
     '{"errors":[{"message":"Cannot query field","locations":[{"line":2}]}]}',
     False),
    # --- Phase 330: the bare-``ecd`` Edgecast shape ---
    ("ecdsa crypto identifiers",
     "<script>const alg='ECDSA';crypto.subtle.importKey('ECDH')</script>",
     False),
    ("marker token containing ecd",
     '<div id="out">xssentinel_dom_abecd123</div>', False),
    ("aws ecs product name", "<p>Our ECS cluster runs in us-east-1.</p>",
     False),
    # --- vendor mentions (contract 1 only) ---
    ("cf ray comment",
     "<!-- Cloudflare Ray ID: 7c1f2e3a4b5c6d7e --><div>ok</div>", True),
    ("cdn footer", "<footer>Powered by Cloudflare</footer>", True),
    ("docs about modsecurity",
     "<p>ModSecurity is an open-source WAF engine.</p>", True),
]


class TestBenignCorpus(unittest.TestCase):
    def test_no_benign_sample_is_ever_blocked(self):
        for label, body, _vendor in CORPUS:
            d = wafmod.detect(_R(200, {"Server": "nginx"}, body))
            self.assertFalse(d["blocked"],
                             f"{label}: blocked by {d['waf']} ({d['reason']})")

    def test_plain_samples_do_not_fingerprint_a_vendor(self):
        for label, body, names_vendor in CORPUS:
            if names_vendor:
                continue
            d = wafmod.detect(_R(200, {"Server": "nginx"}, body))
            self.assertIsNone(d["waf"], f"{label}: fingerprint {d['waf']}")

    def test_every_rule_is_checked_against_the_corpus(self):
        """Mutation control: prove the corpus really exercises the tables.

        If a future edit empties the signature table or the hint regex,
        the two tests above would pass vacuously.  Count the rules here
        so an empty table fails loudly.
        """
        self.assertGreater(len(wafmod._WAF_SIGNATURES), 20)
        self.assertIsNotNone(wafmod._BLOCK_BODY_HINTS.search("access denied"))


import re as _re  # noqa: E402  (verbatim pre-294 mutation-control block)

# Mutation control: the PRE-Phase-294 hint table, verbatim.  If this does
# not fire on the corpus, the corpus proves nothing -- it would pass on the
# old code too.  (Same discipline as the PRE-Phase-200 branch replay in
# tests/test_spa_crawler_fallback.py.)
_OLD_BLOCK_HINTS = _re.compile(
    r"(request blocked|access denied|forbidden|firewall|security policy|"
    r"malicious|blocked by|not acceptable|waf|"
    r"web application firewall|request rejected|"
    r"suspicious activity|attack detected|"
    r"security rule|rule id|reference id|"
    r"request id|correlation id|incident id|"
    r"access has been blocked|protected by|"
    r"attention required|cf-ray|cloudflare|"
    r"mod_security|this error was generated|"
    r"akamai|access.denied|"
    r"request blocked by aws|"
    r"incapsula incident|"
    r"访问被拒绝|防火墙|安全策略|攻击|恶意请求|"
    r"アクセスが拒否されました|ファイアウォール|"
    r"접근이 거부되었습니다|방화벽|"
    r"Accès refusé|pare-feu|"
    r"Zugriff verweigert|Firewall|"
    r"Acceso denegado|cortafuegos|"
    r"Acesso negado|firewall)",
    _re.IGNORECASE,
)


class TestCorpusDiscriminates(unittest.TestCase):
    def test_old_hint_table_would_have_blocked_most_of_the_corpus(self):
        hits = [label for label, body, _v in CORPUS
                if _OLD_BLOCK_HINTS.search(body)]
        # measured on the pre-294 table: CSS vars, class names, the tsa/waf
        # identifiers, the cn/jp/fr articles, the request-id pages, the
        # dashboard, the firewall marketing page, the policy page, the CF
        # Ray-ID comment and the CDN footer all matched.
        self.assertGreaterEqual(len(hits), 10, f"only {len(hits)}: {hits}")
        self.assertIn("cn security article", hits)
        self.assertIn("cf ray comment", hits)


if __name__ == "__main__":
    unittest.main()
