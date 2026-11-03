# Real-world XSS regression v2 — Juice Shop 20.2.0 + DVWA

Generated: 2026-11-03T18:23:18

Apps: `juice` http://127.0.0.1:3000 (bkimminich/juice-shop:v20.2.0); `juice_unsafe` http://127.0.0.1:3003 (bkimminich/juice-shop:v20.2.0); `dvwa` http://127.0.0.1:8080 (ghcr.io/digininja/dvwa)

| tool | status | TP | FN | FP | TN | blocked | recall | FPR | wall(s) |
|---|---|---|---|---|---|---|---|---|---|
| zap | unavailable | 0 | 0 | 0 | 0 | 13 | 0.000 | 0.000 | 0.0 |

## Per-case

| case | app | category | GT | zap |
|---|---|---|---|---|
| js-dom-search-iframe | juice | dom | vulnerable | BLOCKED |
| js-dom-search-onerror | juice | dom | vulnerable | BLOCKED |
| js-dom-search-script-tag | juice | dom | vulnerable | BLOCKED |
| js-root | juice | control | safe | BLOCKED |
| js-api-search | juice | control | safe | BLOCKED |
| js-api-search-payload | juice | control | safe | BLOCKED |
| js-track-order | juice | control | safe | BLOCKED |
| js-unsafe-api-only | juice_unsafe | api_only | vulnerable | BLOCKED |
| js-unsafe-header | juice_unsafe | header | vulnerable | BLOCKED |
| js-unsafe-product-json-control | juice_unsafe | control | safe | BLOCKED |
| dvwa-auth-reflected | dvwa | reflected | vulnerable | BLOCKED |
| dvwa-auth-stored | dvwa | stored | vulnerable | BLOCKED |
| dvwa-index-control | dvwa | control | safe | BLOCKED |

## Blocked-tool reasons

- `dalfox` / `js-unsafe-api-only`: requires an authenticated API write followed by an SPA product-dialog render; dalfox has a body injector but no authenticated write/render workflow
- `nuclei` / `js-unsafe-api-only`: requires an authenticated PUT /api/Products/:id followed by SPA rendering; DAST templates have no write workflow
- `dalfox` / `js-unsafe-header`: requires an authenticated GET /rest/saveLoginIp with a persisted request header and an SPA render; there is no header-injection workflow in dalfox's URL scanner
- `nuclei` / `js-unsafe-header`: requires an authenticated saveLoginIp header write plus SPA rendering of /#/privacy-security/last-login-ip
- `nuclei` / `dvwa-auth-stored`: the guestbook write is a POST form; the DAST xss templates only fuzz GET parameters, so they never reach this sink

## Caveats
- dalfox/nuclei are URL-shaped scanners. A `#`-fragment DOM case never reaches the sink they can inject into (the fragment is stripped client-side), so those three DOM rows are structurally FN rather than a tuning failure.
- dalfox/nuclei cannot execute an authenticated PUT /api/Products/:id or a header write followed by an SPA render; API-only and header rows are marked BLOCKED, not FN.
- Burp Pro / Acunetix were unavailable on this host (no installation/licence), so their arms are reported as not executed rather than scored.
- Ground truth is from the official challenge catalogue / app source plus an independent Playwright dialog check on 2026-11-03 (see cases.json evidence fields), never from this scanner's own verdict.
