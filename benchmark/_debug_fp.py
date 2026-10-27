"""Debug remaining FPs: CSP + JSONP."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

from xssentinel.core import verifier  # noqa: E402  (sys.path shim above)

# CSP cases
print("=== CSP Cases ===")
token = "xssv_test123"

# neg-csp-01: csp_strict_element - raw reflection + script-src 'self'
html1 = f'<html><body><div><script>alert("{token}")</script></div></body></html>'
headers1 = {"Content-Security-Policy": "script-src 'self'; object-src 'none'; base-uri 'none'"}
r1 = verifier.verify_semantic(html1, token, response_headers=headers1)
print(f"neg-csp-01 (script-src self): {r1}")

# neg-csp-02: csp_strict_href - javascript: URI + default-src 'none'
html2 = f'<html><body><a href="javascript:alert(\'{token}\')">link</a></body></html>'
headers2 = {"Content-Security-Policy": "default-src 'none'; script-src 'none'"}
r2 = verifier.verify_semantic(html2, token, response_headers=headers2)
print(f"neg-csp-02 (default-src none): {r2}")

# neg-csp-03: csp_nonce_element - raw reflection + nonce CSP
html3 = f'<html><body><div><script>alert("{token}")</script></div></body></html>'
headers3 = {"Content-Security-Policy": "script-src 'nonce-k8Fj3x9Qm2Rw7Yp4'"}
r3 = verifier.verify_semantic(html3, token, response_headers=headers3)
print(f"neg-csp-03 (nonce): {r3}")

# JSONP case
print("\n=== JSONP Case ===")
# neg-jsonp-01: jsonp_whitelist - callback is alphanumeric-only
# When scanner sends a probe token like "xssv_abc123", it passes the whitelist
# Response: xssv_abc123({"status": "ok"});
token_jsonp = "xssv_abc123"
html_jsonp = f'{token_jsonp}({{"status": "ok"}});'
headers_jsonp = {"Content-Type": "application/javascript"}
r_jsonp = verifier.verify_semantic(html_jsonp, token_jsonp, response_headers=headers_jsonp)
print(f"neg-jsonp-01 (whitelist): {r_jsonp}")
print(f"  HTML: {html_jsonp}")

# What if the token is in a function call position?
# The token IS the function name - this is actually executable!
# But the whitelist prevents injecting arguments...
# The scanner sees the token reflected in script context and confirms.
