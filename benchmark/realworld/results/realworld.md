# Real-world XSS regression — OWASP Juice Shop 20.2.0

Generated: 2026-11-03T00:21:49  |  Target: `http://127.0.0.1:3000`

| tool | status | TP | FN | FP | TN | recall | FPR | wall(s) |
|---|---|---|---|---|---|---|---|---|
| xssentinel | scored | 3 | 0 | 0 | 4 | 1.000 | 0.000 | 30.4 |
| xssentinel-headless | scored | 3 | 0 | 0 | 4 | 1.000 | 0.000 | 30.4 |
| dalfox | scored | 0 | 3 | 0 | 4 | 0.000 | 0.000 | 59.3 |
| nuclei | scored | 0 | 3 | 0 | 4 | 0.000 | 0.000 | 8.3 |

## Per-case

| case | GT | xssentinel | xssentinel-headless | dalfox | nuclei |
|---|---|---|---|---|---|
| js-dom-search-iframe | vulnerable | TP | TP | FN | FN |
| js-dom-search-onerror | vulnerable | TP | TP | FN | FN |
| js-dom-search-script-tag | vulnerable | TP | TP | FN | FN |
| js-root | safe | TN | TN | TN | TN |
| js-api-search | safe | TN | TN | TN | TN |
| js-api-search-payload | safe | TN | TN | TN | TN |
| js-track-order | safe | TN | TN | TN | TN |

## Caveats
- Cases are anonymous-only. Authenticated Juice Shop challenges (persisted feedback/user, API-only XSS, header XSS) are NOT in this set because the fixed app requires a login flow and product mutations; adding them requires a seeded session (see README).
- dalfox/nuclei arms run in their standard non-headless DAST mode. Their headless layers are host-unstable (see p342 meta), so a fragment-only DOM case is structurally outside their input shape.
- Burp Pro / Acunetix were unavailable on this host (no installation/licence), so their arms are reported as not executed rather than scored.
- Ground truth for the DOM cases is an independent Playwright dialog check (2026-11-02), not this scanner's own verdict.
