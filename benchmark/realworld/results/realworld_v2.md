# Real-world XSS regression v2 — Juice Shop 20.2.0 + DVWA

Generated: 2026-11-03T20:43:28

Apps: `juice` http://127.0.0.1:3000 (bkimminich/juice-shop:v20.2.0); `juice_unsafe` http://127.0.0.1:3003 (bkimminich/juice-shop:v20.2.0); `bwapp` http://127.0.0.1:8081 (docker.1ms.run/raesene/bwapp); `selfhosted` http://127.0.0.1:8090 (local source (no container image)); `dvwa` http://127.0.0.1:8080 (ghcr.io/digininja/dvwa)

| tool | status | TP | FN | FP | TN | blocked | recall | FPR | wall(s) |
|---|---|---|---|---|---|---|---|---|---|
| xssentinel | scored | 13 | 0 | 0 | 9 | 0 | 1.000 | 0.000 | 95.8 |
| xssentinel-headless | scored | 13 | 0 | 0 | 9 | 0 | 1.000 | 0.000 | 106.4 |
| dalfox | scored | 4 | 3 | 0 | 9 | 6 | 0.571 | 0.000 | 133.7 |
| nuclei | scored | 3 | 3 | 0 | 9 | 7 | 0.500 | 0.000 | 6.7 |

## Per-case

| case | app | category | GT | xssentinel | xssentinel-headless | dalfox | nuclei |
|---|---|---|---|---|---|---|---|
| js-dom-search-iframe | juice | dom | vulnerable | TP | TP | FN | FN |
| js-dom-search-onerror | juice | dom | vulnerable | TP | TP | FN | FN |
| js-dom-search-script-tag | juice | dom | vulnerable | TP | TP | FN | FN |
| js-root | juice | control | safe | TN | TN | TN | TN |
| js-api-search | juice | control | safe | TN | TN | TN | TN |
| js-api-search-payload | juice | control | safe | TN | TN | TN | TN |
| js-track-order | juice | control | safe | TN | TN | TN | TN |
| js-unsafe-api-only | juice_unsafe | api_only | vulnerable | TP | TP | BLOCKED | BLOCKED |
| js-unsafe-header | juice_unsafe | header | vulnerable | TP | TP | BLOCKED | BLOCKED |
| js-unsafe-product-json-control | juice_unsafe | control | safe | TN | TN | TN | TN |
| dvwa-auth-reflected | dvwa | reflected | vulnerable | TP | TP | TP | TP |
| dvwa-auth-stored | dvwa | stored | vulnerable | TP | TP | TP | BLOCKED |
| dvwa-index-control | dvwa | control | safe | TN | TN | TN | TN |
| sh-reflected | selfhosted | reflected | vulnerable | TP | TP | TP | TP |
| sh-reflected-safe | selfhosted | control | safe | TN | TN | TN | TN |
| sh-stored | selfhosted | stored | vulnerable | TP | TP | BLOCKED | BLOCKED |
| sh-header | selfhosted | header | vulnerable | TP | TP | BLOCKED | BLOCKED |
| sh-root-control | selfhosted | control | safe | TN | TN | TN | TN |
| bw-reflected | bwapp | reflected | vulnerable | TP | TP | TP | TP |
| bw-stored | bwapp | stored | vulnerable | TP | TP | BLOCKED | BLOCKED |
| bw-header | bwapp | header | vulnerable | TP | TP | BLOCKED | BLOCKED |
| bw-portal-control | bwapp | control | safe | TN | TN | TN | TN |

## Blocked-tool reasons

- `dalfox` / `js-unsafe-api-only`: requires an authenticated API write followed by an SPA product-dialog render; dalfox has a body injector but no authenticated write/render workflow
- `nuclei` / `js-unsafe-api-only`: requires an authenticated PUT /api/Products/:id followed by SPA rendering; DAST templates have no write workflow
- `dalfox` / `js-unsafe-header`: requires an authenticated GET /rest/saveLoginIp with a persisted request header and an SPA render; there is no header-injection workflow in dalfox's URL scanner
- `nuclei` / `js-unsafe-header`: requires an authenticated saveLoginIp header write plus SPA rendering of /#/privacy-security/last-login-ip
- `nuclei` / `dvwa-auth-stored`: the guestbook write is a POST form; the DAST xss templates only fuzz GET parameters, so they never reach this sink
- `dalfox` / `sh-stored`: requires a login session plus a POST write and a re-read; the URL scanner has no stored workflow
- `nuclei` / `sh-stored`: requires a login session plus a POST write and a re-read; DAST templates do not submit forms
- `dalfox` / `sh-header`: requires a login cookie and an attacker-controlled User-Agent header; dalfox's URL arm has no header-injection workflow
- `nuclei` / `sh-header`: requires a login cookie and a header-injection workflow; DAST xss templates only fuzz GET parameters
- `dalfox` / `bw-stored`: requires a login session plus a POST blog write and a re-read; no stored workflow
- `nuclei` / `bw-stored`: requires a login session plus a POST blog write and a re-read; DAST templates do not submit forms
- `dalfox` / `bw-header`: requires a login cookie and an attacker-controlled User-Agent; no header-injection workflow
- `nuclei` / `bw-header`: requires a login cookie and header injection; DAST xss templates only fuzz GET parameters

## Caveats
- dalfox/nuclei are URL-shaped scanners. A `#`-fragment DOM case never reaches the sink they can inject into (the fragment is stripped client-side), so those three DOM rows are structurally FN rather than a tuning failure.
- dalfox/nuclei cannot execute an authenticated PUT /api/Products/:id or a header write followed by an SPA render; API-only and header rows are marked BLOCKED, not FN.
- Burp Pro / Acunetix were unavailable on this host (no installation/licence), so their arms are reported as not executed rather than scored.
- Ground truth is from the official challenge catalogue / app source plus an independent Playwright dialog check on 2026-11-03 (see cases.json evidence fields), never from this scanner's own verdict.
