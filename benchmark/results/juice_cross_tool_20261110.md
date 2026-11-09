# Cross-tool per-case matrix on a real application (FACT TABLE)

- generated (UTC): `2026-11-09T16:31:54+00:00`
- tree: `7d3b9f7` / target: `http://127.0.0.1:18900`
- app: OWASP Juice Shop v20.2.0 (official node22_win32_x64 release)
- answer key: `dev/_juiceshop/app/juice-shop_20.2.0/data/static/challenges.yml`

> **FACT TABLE ONLY. No TP/FP/TN/FN or F1: delivery reachability differs per tool and there is no server-deliverable positive.**

## Tool versions (actually invoked)

- **XSSentinel**: `this checkout (7d3b9f7)`
- **dalfox**: `░█████▓          ░████▒       ░         Dalfox v2.13.0`
- **nuclei-dast-xss**: `[[34mINF[0m] Nuclei Engine Version: v3.9.0`
- **nuclei templates**: `C:\Users\Administrator\nuclei-templates\dast\vulnerabilities\xss`

## Case set

| id | ground truth | answer key | fragment | in denominator |
|---|---|---|---|---|
| `js-dom-search` | pos | localXssChallenge (DOM XSS) | True | True |
| `js-dom-track-result` | pos | reflectedXssChallenge (Reflected XSS) | True | True |
| `js-api-search` | neg | measured control: surfaces reflects=False | False | True |
| `js-redirect` | neg | measured control: writes escaped_iframe=True | False | True |
| `js-dom-search-result` | pos-derived | — | True | False |

## Per-case results

| tool | case | detected | error | fragment | secs |
|---|---|---|---|---|---|
| XSSentinel | `js-dom-search` | True | — | True | 6.85 |
| XSSentinel | `js-dom-track-result` | True | — | True | 6.54 |
| XSSentinel | `js-api-search` | False | — | False | 1.58 |
| XSSentinel | `js-redirect` | False | — | False | 1.65 |
| XSSentinel | `js-dom-search-result` | True | — | True | 6.45 |
| dalfox | `js-dom-search` | False | dalfox rc=2 | True | 1.19 |
| dalfox | `js-dom-track-result` | False | dalfox rc=2 | True | 0.97 |
| dalfox | `js-api-search` | False | — | False | 18.6 |
| dalfox | `js-redirect` | False | — | False | 7.54 |
| dalfox | `js-dom-search-result` | False | dalfox rc=2 | True | 0.96 |
| nuclei-dast-xss | `js-dom-search` | False | — | True | 180.63 |
| nuclei-dast-xss | `js-dom-track-result` | False | — | True | 180.52 |
| nuclei-dast-xss | `js-api-search` | False | — | False | 180.59 |
| nuclei-dast-xss | `js-redirect` | False | — | False | 180.56 |
| nuclei-dast-xss | `js-dom-search-result` | False | — | True | 180.52 |

## Counts (NOT a confusion matrix)

| tool | cases | detected | errors | wall s | on fragment | on server |
|---|---|---|---|---|---|---|
| XSSentinel | 5 | 3 | 0 | 23.07 | 3 | 0 |
| dalfox | 5 | 0 | 3 | 29.26 | 0 | 0 |
| nuclei-dast-xss | 5 | 0 | 0 | 902.82 | 0 | 0 |

## Why no score

1. A URL fragment is not transmitted in an HTTP request. Any tool whose input model is an HTTP request cannot be handed the injection point on the three hash-route rows; a zero there is **not measured**, not a miss.
2. Both server-reachable rows are true negatives (REST search does not reflect; /redirect HTML-escapes). There is no server-deliverable positive, so TP and recall have no denominator.
3. Tool configurations differ by nature (e.g. nuclei's DAST set contains a browser-driven `dom-xss.yaml`, dalfox is request-only, and this repo's adapter runs XSSentinel at gate budgets WITHOUT `--headless`). The earlier `--headless` Juice Shop run is a DIFFERENT configuration and is deliberately not mixed in.
4. Therefore TP/FP/TN/FN, precision, recall and F1 would all be fabricated precision. This table reports what each tool actually emitted on the identical URL, nothing more.
