"""Quick verification of verifier fixes."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

from xssentinel.core import verifier  # noqa: E402  (sys.path shim above)

# Test 1: Normal script block should still confirm
r = verifier.verify_semantic('<script>alert("tok_x")</script>', 'tok_x')
assert r["confirmed"] is True, f"FAIL: script block should confirm: {r}"
print(f"PASS: script block confirms: {r['context']}")

# Test 2: RCDATA textarea should NOT confirm
r = verifier.verify_semantic('<textarea><script>alert("tok_y")</script></textarea>', 'tok_y')
assert r["confirmed"] is False, f"FAIL: textarea RCDATA should not confirm: {r}"
print(f"PASS: textarea RCDATA blocked: {r['detail']}")

# Test 3: RCDATA title should NOT confirm
r = verifier.verify_semantic('<html><head><title><img src=x onerror=alert("tok_t")></title></head><body></body></html>', 'tok_t')
assert r["confirmed"] is False, f"FAIL: title RCDATA should not confirm: {r}"
print(f"PASS: title RCDATA blocked: {r['detail']}")

# Test 4: CSP strict should NOT confirm
r = verifier.verify_semantic('<script>alert("tok_c")</script>', 'tok_c',
                             {"Content-Security-Policy": "script-src 'self'; object-src 'none'"})
assert r["confirmed"] is False, f"FAIL: CSP strict should not confirm: {r}"
print(f"PASS: CSP blocks inline: {r['detail']}")

# Test 5: CSP nonce should NOT confirm
r = verifier.verify_semantic('<script>alert("tok_n")</script>', 'tok_n',
                             {"Content-Security-Policy": "script-src 'nonce-abc123'"})
assert r["confirmed"] is False, f"FAIL: CSP nonce should not confirm: {r}"
print(f"PASS: CSP nonce blocks: {r['detail']}")

# Test 6: No CSP should still confirm
r = verifier.verify_semantic('<script>alert("tok_ok")</script>', 'tok_ok',
                             {"Content-Type": "text/html"})
assert r["confirmed"] is True, f"FAIL: no CSP should confirm: {r}"
print("PASS: no CSP confirms normally")

# Test 7: JS string trapping should NOT confirm
script = 'var x = "\\"\\"><\\/script><script>alert(\'tok_js\')<\\/script>";'
html_page = f'<script>{script}</script>'
r = verifier.verify_semantic(html_page, 'tok_js')
assert r["confirmed"] is False, f"FAIL: JS string trapped should not confirm: {r}"
print(f"PASS: JS string trapping blocked: {r.get('detail','')}")

# Test 8: Event handler should still confirm
r = verifier.verify_semantic('<img src=x onerror="alert(\'tok_evt\')">', 'tok_evt')
assert r["confirmed"] is True, f"FAIL: event handler should confirm: {r}"
print(f"PASS: event handler confirms: {r['context']}")

# Test 9: javascript: URI should still confirm
r = verifier.verify_semantic('<a href="javascript:alert(\'tok_uri\')">x</a>', 'tok_uri')
assert r["confirmed"] is True, f"FAIL: javascript URI should confirm: {r}"
print(f"PASS: javascript URI confirms: {r['context']}")

# Test 10: html.escape'd should NOT confirm (existing behavior)
r = verifier.verify_semantic('&lt;svg/onload=alert(\'tok_esc\')&gt;', 'tok_esc')
assert r["confirmed"] is False, f"FAIL: escaped should not confirm: {r}"
print("PASS: escaped payload not confirmed")

# Test 11: CSP with unsafe-inline SHOULD confirm (not blocking)
r = verifier.verify_semantic('<script>alert("tok_ui")</script>', 'tok_ui',
                             {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
assert r["confirmed"] is True, f"FAIL: CSP unsafe-inline should confirm: {r}"
print("PASS: CSP unsafe-inline allows execution")

print("\n=== ALL VERIFIER TESTS PASS ===")
