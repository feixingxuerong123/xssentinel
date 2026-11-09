# Per-challenge DELIVERY facts on a real application (FACT TABLE)

- generated (UTC): `2026-11-09T17:21:12+00:00`
- tree: `f9ec777` / target: `http://127.0.0.1:18900`
- answer key: `dev/_juiceshop/app/juice-shop_20.2.0/data/static/challenges.yml`
- official XSS challenges: 9; already covered by the 2026-11-09 run: localXssChallenge, reflectedXssChallenge

> **FACT TABLE ONLY. Delivery reachability and server echoes are measured; no TP/FP/TN/FN, precision, recall or F1, and no exploitation verdict. A stored string in a JSON field is not a rendered XSS.**

## Delivery facts (one row per uncovered official challenge)

| key | difficulty | shape | HTTP reachable | sent | req | view | payload in resp / view | server echo | verdict |
|---|---|---|---|---|---|---|---|---|---|
| `restfulXssChallenge` | 3 | `http_json` | True | True | 200 | 200 | True / True | `<iframe src="javascript:alert(`xss`)">` | `delivered` |
| `persistedXssUserChallenge` | 3 | `http_json` | True | True | 201 | 200 | False / None | `rc="javascript:alert(`xss`)">` | `accepted_not_reflected` |
| `persistedXssFeedbackChallenge` | 4 | `http_json` | True | True | 201 | — | False / None | `—` | `accepted_not_reflected` |
| `httpHeaderXssChallenge` | 4 | `http_header` | True | True | 200 | — | True / None | `<iframe src="javascript:alert(`xss`)">` | `delivered` |
| `usernameXssChallenge` | 4 | `http_query` | True | True | 200 | — | False / None | `—` | `accepted_not_reflected` |
| `videoXssChallenge` | 6 | `not_attempted` | False | False | — | — | None / None | `—` | `blocked` |
| `xssBonusChallenge` | 1 | `url_fragment` | False | False | — | — | None / None | `—` | `fragment_only` |

## Reasons and server echoes

- **`restfulXssChallenge`** (API-only XSS): this request's own response reported the exact payload in a decoded field (stored, NOT proven rendered)
  - response: `{"status":"success","data":{"id":1,"name":"Apple Juice (1000ml)","description":"<iframe src=\"javascript:alert(`xss`)\">","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg",`
  - decoded server echo: `<iframe src="javascript:alert(`xss`)">`
- **`persistedXssUserChallenge`** (Client-side XSS Protection): 2xx accepted the request, but the decoded readback does not equal the payload (sanitized, rewritten, or not reflected); see server_echo_value
  - response: `{"status":"success","data":{"deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/default.svg","isActive":true,"id":29,"email":"phase381_1794244866`
  - decoded server echo: `rc="javascript:alert(`xss`)">`
- **`persistedXssFeedbackChallenge`** (Server-side XSS Protection): 2xx accepted the request, but the decoded readback does not equal the payload (sanitized, rewritten, or not reflected); see server_echo_value
  - response: `{"status":"success","data":{"id":12,"comment":"","rating":5,"updatedAt":"2026-11-09T17:21:06.224Z","createdAt":"2026-11-09T17:21:06.224Z","UserId":null}}`
- **`httpHeaderXssChallenge`** (HTTP-Header XSS): this request's own response reported the exact payload in a decoded field (stored, NOT proven rendered)
  - response: `{"id":1,"username":"","email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500","role":"admin","deluxeToken":"","lastLoginIp":"<iframe src=\"javascript:alert(`xss`)`
  - decoded server echo: `<iframe src="javascript:alert(`xss`)">`
  - supplementary JWT lastLoginIp snapshot contains payload: True
- **`usernameXssChallenge`** (CSP Bypass): 2xx accepted the request, but the decoded readback does not equal the payload (sanitized, rewritten, or not reflected); see server_echo_value
  - response: `<!-- ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors. ~ SPDX-License-Identifier: MIT --> <!doctype html> <html lang="en" data-beasties-container> <he`
- **`videoXssChallenge`** (Video XSS): The official hints state this requires the file-write vulnerability behind another 6-star challenge; that prerequisite was not obtained on this deployment, so no request was sent and nothing is inferred.
- **`xssBonusChallenge`** (Bonus Payload): The injection point is in the URL fragment; no HTTP request can carry it (objective URL shape).
  - XSSentinel CLI (fact, not a verdict): rc=0, 6.47s, finding types=['dom_dynamic']

## Counts (NOT a confusion matrix)

| verdict | rows |
|---|---|
| `accepted_not_reflected` | 3 |
| `blocked` | 1 |
| `delivered` | 2 |
| `fragment_only` | 1 |

## Why no score

1. These seven are not seven independent targets and not seven comparable cases: two are hash-route/fragment shaped, four need an authenticated write followed by an SPA render, and one needs a separate 6-star file-write prerequisite.
2. This runner measures DELIVERY and server echoes only. A payload stored in a JSON field says nothing about whether the SPA renders it as HTML; browser execution needs its own Playwright evidence and is deliberately not claimed here.
3. A blocked row was never sent. Counting it as a miss, or turning `delivered` into a true positive, would fabricate a denominator. No TP/FP/TN/FN, precision, recall or F1 is produced.
4. The 2026-11-09 five-surface run and the 2026-11-10 cross-tool table used different configurations (`--headless` vs gate budgets); none of them are merged into this table.
5. Only each request's OWN response decides a verdict. Persisted state from earlier runs (a user list, a login-IP snapshot) is kept as supplementary information, never as this run's evidence.
