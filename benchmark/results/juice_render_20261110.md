# Independent browser evidence for the delivered rows (FACT TABLE)

- generated (UTC): `2026-11-09T17:50:25+00:00`
- tree: `edfe91d` / target: `http://127.0.0.1:18900`
- browser: independent Playwright Chromium, headless, dialog oracle
- wall: 15.54s / rows: 4

> **FACT TABLE ONLY. Independent Chromium dialog/DOM evidence per arm; no TP/FP/TN/FN, precision, recall or F1. A dialog in the control arm means contamination, not a detection.**

## Matched payload / control arms

| key | arm | inject | server has payload | dialogs | iframes | payload in DOM | verdict |
|---|---|---|---|---|---|---|---|
| `httpHeaderXssChallenge` | `payload` | 200 | True | ['xss'] | 1 | True | `browser_executed` |
| `httpHeaderXssChallenge` | `control` | 200 | False | [] | 0 | False | `not_executed` |
| `restfulXssChallenge` | `payload` | 200 | True | ['xss'] | 1 | True | `browser_executed` |
| `restfulXssChallenge` | `control` | 200 | False | [] | 0 | False | `not_executed` |

## Per-arm detail

- **`httpHeaderXssChallenge` / `payload`** → `browser_executed`
  - setup: True-Client-IP header -> fresh-login JWT -> SPA route
  - view: `http://127.0.0.1:18900/#/privacy-security/last-login-ip`
  - server echo: `<iframe src="javascript:alert(`xss`)">`
  - DOM: html_len=190217, javascript_src=True
- **`httpHeaderXssChallenge` / `control`** → `not_executed`
  - setup: True-Client-IP header -> fresh-login JWT -> SPA route
  - view: `http://127.0.0.1:18900/#/privacy-security/last-login-ip`
  - server echo: `203.0.113.7`
  - DOM: html_len=190173, javascript_src=False
- **`restfulXssChallenge` / `payload`** → `browser_executed`
  - setup: PUT /api/Products/1 description -> dispatch_event click on the product info section (the app's welcome overlay blocks real pointer clicks; BOTH arms use the same method)
  - view: `http://127.0.0.1:18900/#/search?q=Apple` + click `mat-card section[role=button]` via `dispatch_event`
  - server echo: `<iframe src="javascript:alert(`xss`)">`
  - DOM: html_len=240080, javascript_src=True
- **`restfulXssChallenge` / `control`** → `not_executed`
  - setup: PUT /api/Products/1 description -> dispatch_event click on the product info section (the app's welcome overlay blocks real pointer clicks; BOTH arms use the same method)
  - view: `http://127.0.0.1:18900/#/search?q=Apple` + click `mat-card section[role=button]` via `dispatch_event`
  - server echo: `The all-time classic.`
  - DOM: html_len=240054, javascript_src=False

## Counts (NOT a confusion matrix)

| verdict | rows |
|---|---|
| `browser_executed` | 2 |
| `not_executed` | 2 |

## Why no score

1. Two rows with different delivery shapes (an authenticated header write vs a product description write) and an SPA-click prerequisite are not two comparable cases; there is no denominator.
2. Execution evidence is a real ``dialog`` event. An iframe in the DOM, a stored string, or the product's own finding is not execution.
3. Each payload arm has a matched clean control. A dialog in the control arm is reported as contamination, never as a hit.
4. A ``not_executed`` result on this official v20.2.0 build is a fact about this target, not a verdict on the scanner.
