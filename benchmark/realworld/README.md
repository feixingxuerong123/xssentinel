# Real-world XSS regression (OWASP Juice Shop + DVWA)

This directory is a **fixed third-party application target**, scored separately from
`benchmark/manifest.json`'s self-authored matrix. Its purpose is to answer one
question the self-authored matrix cannot: *does the detector still work on an
application we did not build?*

v1 (2026-11-02) covered seven anonymous Juice Shop surfaces. v2 (2026-11-03)
adds login-required reflected XSS, persistent-comment stored XSS, API-only
stored XSS and HTTP-header XSS, using digest-pinned images. v2.1 adds a
self-hosted four-face target; v2.2 adds bWAPP (reflected GET, stored blog,
User-Agent header, login) as a third real application. The old v1
artifacts remain in `results/realworld.json` / `results/realworld.md`; v2 is
written to `results/realworld_v2.json` / `results/realworld_v2.md`.

## Targets (pinned)

| key | app | image (digest-pinned) | base URL | auth |
|---|---|---|---|---|
| `juice` | OWASP Juice Shop 20.2.0 | `bkimminich/juice-shop:v20.2.0` — `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b` | `http://127.0.0.1:3000` | anonymous |
| `juice_unsafe` | OWASP Juice Shop 20.2.0 (`NODE_ENV=unsafe`) | same digest | `http://127.0.0.1:3003` | `admin@juice-sh.op` / `admin123` |
| `dvwa` | DVWA | `ghcr.io/digininja/dvwa@sha256:1af2cedda7617e4d22937e61c98bbf71d8b74b98e46f5e41dd6aa0a5183311b0` | `http://127.0.0.1:8080` | `admin` / `password`, security `low` |
| `bwapp` | bWAPP 2.2 | `docker.1ms.run/raesene/bwapp@sha256:2f41183ea9f9e8fb36678d7a2a0c8a9db9a59f4569cee02fe6664b419b2600ee` | `http://127.0.0.1:8081` | `bee` / `bug`, `security_level=0` |
| `selfhosted` | Self-hosted XSS lab (local source, no image) | `benchmark/realworld/selfhosted/app.py` | `http://127.0.0.1:8090` | `admin/adminpass` (admin), `alice/alicepass` (user) |

Start them:

```bash
# anonymous Juice Shop
docker run -d --name juice-official -p 127.0.0.1:3000:3000 \
    bkimminich/juice-shop:v20.2.0

# authenticated Juice Shop: config/unsafe.yml sets challenges.safetyMode=disabled,
# which re-enables the challenges whose disabledEnv lists Docker
# (restfulXssChallenge, httpHeaderXssChallenge). Verified in the image:
# build/models/product.js and build/routes/saveLoginIp.js only sanitize when
# utils.isChallengeEnabled(...) is false.
docker run -d --name juice-unsafe -p 127.0.0.1:3003:3000 \
    -e NODE_ENV=unsafe bkimminich/juice-shop:v20.2.0

# DVWA + MariaDB (digest for DVWA; mariadb:11 digest 6422478c...a331f15)
docker network create dvwa-net
docker run -d --name dvwa-db --network dvwa-net \
    -e MARIADB_ROOT_PASSWORD=rootpass -e MARIADB_DATABASE=dvwa \
    -e MARIADB_USER=dvwa -e MARIADB_PASSWORD=p@ssw0rd mariadb:11
docker run -d --name dvwa-official --network dvwa-net \
    -p 127.0.0.1:8080:80 -e DB_SERVER=dvwa-db -e DEFAULT_SECURITY_LEVEL=low \
    ghcr.io/digininja/dvwa@sha256:1af2cedda7617e4d22937e61c98bbf71d8b74b98e46f5e41dd6aa0a5183311b0
```

Restart the containers to reset state: `docker restart juice-unsafe dvwa-official`
(or recreate `juice-unsafe` if a product description was overwritten).

bWAPP (image ships MySQL; the install step creates the bWAPP schema):

```bash
docker run -d --name bwapp -p 127.0.0.1:8081:80 \
  docker.1ms.run/raesene/bwapp@sha256:2f41183ea9f9e8fb36678d7a2a0c8a9db9a59f4569cee02fe6664b419b2600ee
curl 'http://127.0.0.1:8081/install.php?install=yes'
```

Self-hosted four-face target (SQLite in memory; restart to clear stored comments):

```bash
python benchmark/realworld/selfhosted/app.py --port 8090
```

## Cases (22)

| id | app | category | GT | ground-truth source / independent check |
|---|---|---|---|---|
| `js-dom-search-iframe` | juice | dom | vulnerable | `localXssChallenge`; Playwright dialog `1` |
| `js-dom-search-onerror` | juice | dom | vulnerable | same sink, second carrier; Playwright dialog `1` |
| `js-dom-search-script-tag` | juice | dom | vulnerable | same sink; endpoint-level GT (this payload is inert) |
| `js-root` | juice | control | safe | no attacker input |
| `js-api-search` | juice | control | safe | JSON, no HTML execution context |
| `js-api-search-payload` | juice | control | safe | JSON; query never rendered as HTML |
| `js-track-order` | juice | control | safe | JSON; path segment echoed, never rendered |
| `js-unsafe-api-only` | juice_unsafe | api_only | vulnerable | `restfulXssChallenge`; PUT `/api/Products/1` description=`<iframe …>`, Playwright dialog `xss` after product-card click |
| `js-unsafe-header` | juice_unsafe | header | vulnerable | `httpHeaderXssChallenge`; GET `/rest/saveLoginIp` with `True-Client-IP`, fresh login, Playwright dialog `xss` on `/#/privacy-security/last-login-ip` |
| `js-unsafe-product-json-control` | juice_unsafe | control | safe | same PUT endpoint read back as JSON: payload string in `application/json`, never parsed as HTML |
| `dvwa-auth-reflected` | dvwa | reflected | vulnerable | `vulnerabilities/xss_r/source/low.php`; Playwright dialog `1` |
| `dvwa-auth-stored` | dvwa | stored | vulnerable | `vulnerabilities/xss_s/source/low.php`; persist guestbook comment, Playwright dialog `1` |
| `dvwa-index-control` | dvwa | control | safe | authenticated landing page, no attacker input |
| `sh-reflected` | selfhosted | reflected | vulnerable | `/reflect` raw query; Playwright dialog |
| `sh-reflected-safe` | selfhosted | control | safe | `/reflect-safe` uses `html.escape`; Playwright no dialog |
| `sh-stored` | selfhosted | stored | vulnerable | `/guestbook` SQLite insert + raw render; alice writes, admin and alice view -> dialog |
| `sh-header` | selfhosted | header | vulnerable | `/header` raw `User-Agent` / `X-Forwarded-For`; alice session -> dialog |
| `sh-root-control` | selfhosted | control | safe | login page, no attacker input |
| `bw-reflected` | bwapp | reflected | vulnerable | `bugs.txt`: "Cross-Site Scripting - Reflected (GET)", `xss_get.php`; Playwright dialog |
| `bw-stored` | bwapp | stored | vulnerable | `bugs.txt`: "Cross-Site Scripting - Stored (Blog)", `xss_stored_1.php`; own + "Show all" view dialog |
| `bw-header` | bwapp | header | vulnerable | `bugs.txt`: "Cross-Site Scripting - Reflected (User-Agent)", `xss_user_agent.php`; Playwright dialog |
| `bw-portal-control` | bwapp | control | safe | authenticated `portal.php`, no attacker input |

Ground truth never comes from this scanner's output. DOM cases use the
official challenge catalogue plus a Playwright dialog check; DVWA cases use the
application's own low-security source file plus a Playwright dialog check;
bWAPP cases use the application's official `bugs.txt` catalogue labels
("Reflected (GET)", "Stored (Blog)", "Reflected (User-Agent)") plus a Playwright
dialog check; self-hosted cases are vulnerable by construction AND
independently confirmed with Playwright dialogs (2026-11-03).
Evidence dates are recorded per case in `cases.json`.

Coverage of the four requested classes:

| class | case | requires |
|---|---|---|
| login-required reflected | `dvwa-auth-reflected` | form login → session cookie |
| persistent feedback / stored | `dvwa-auth-stored` | login → POST guestbook → re-read |
| API-only | `js-unsafe-api-only` | bearer login → `PUT /api/Products/1` → SPA dialog |
| header injection | `js-unsafe-header` | bearer login → `GET /rest/saveLoginIp` → re-login → SPA route |

**Not included:** Juice Shop's `persistedXssFeedbackChallenge`. Even with
`safetyMode=disabled` the feedback model still runs `sanitizeHtml(comment)`
(build/models/feedback.js), which strips the official `<iframe>`; the challenge
needs a sanitizer-bypass payload, not a stable regression fixture. The stored
class is therefore represented by DVWA's guestbook, which is unambiguous.

Detection contract: a finding of type
`reflected / stored / stored_dom / dom / dom_dynamic / header_xss /
cookie_xss / path_xss` with severity `medium/high/critical` counts; low
reachability hints and non-XSS audits (CORS, XS-Leaks, outdated JS, SQLi) do not.

## Run

```bash
python benchmark/realworld/run_realworld.py
python benchmark/realworld/run_realworld.py --tools xssentinel,xssentinel-headless,dalfox,nuclei
python benchmark/realworld/run_realworld.py --only js-unsafe-header
python benchmark/realworld/run_realworld.py --tools burp,acunetix   # explicit unavailable report
```

Outputs:

- `results/realworld_v2.json` — per case × tool, with the exact seeded state
- `results/realworld_v2.md` — totals, per-case matrix, blocked reasons

The runner logs in and performs each case's write setup before every tool run,
so all tools see the same mutable state. `--base KEY=URL` overrides a
`base_url`; `--only id1,id2` filters cases for debugging.

Tool flags:

| tool | command shape | note |
|---|---|---|
| `xssentinel` | `-m xssentinel -u URL -f json --max-payloads 14 --max-transforms 12 --threads 2 --timeout 10` plus case auth/stored flags | sync; `-b` cookie for DVWA, `--login-json` for Juice Shop (now seeds both `Authorization` and browser localStorage) |
| `xssentinel-headless` | same `+ --headless` | forces the real-browser DOM confirmation |
| `dalfox` | `dalfox url URL --format json --silence --skip-headless` (+ `-C`, `-H`, and `-X`/`-d` for the DVWA POST form) | v2.13.0; headless layer skipped (host-unstable) |
| `nuclei` | `nuclei -u URL -dast -t ~/nuclei-templates/dast/vulnerabilities/xss -jsonl -silent` (+ `-H` for auth) | v3.9.0 |
| `burp` / `acunetix` | n/a | **unavailable on this host** (no installation/licence); arms report `unavailable`, never scored |
| `zap` | n/a | **unavailable**: `ghcr.io/zaproxy/zap-stable` denied, Docker Hub mirror TLS timeout, GitHub unreachable, no local install |

Binaries can be overridden with `DALFOX_BIN`, `NUCLEI_BIN`,
`NUCLEI_XSS_TEMPLATES`. Commercial endpoints would be `BURP_REST_URL` /
`ACUNETIX_URL`; the adapters are not implemented, so a configured endpoint is
reported as `not-executed` rather than given a fake score.

## Honest reading of the table

- Fragment-only URLs (`/#/search?...`) are never sent to a server. dalfox and
  nuclei cannot see them by design; their FN there is an input-shape limit,
  not a database of missed XSS.
- API-only and header cases are marked **BLOCKED** for dalfox/nuclei: they need
  an authenticated write/mutation followed by an SPA render, which neither tool
  provides. They are excluded from those tools' recall denominators and counted
  in the `blocked` column; they are not silently scored as FN.
- DVWA's guestbook write is a POST form. dalfox is given the form body
  (`-X POST -d ...`); nuclei's DAST templates only fuzz GET parameters, so that
  row is BLOCKED for nuclei.
- `xssentinel` without `--headless` can only reach the DOM layer statically;
  the browser-executed tier is what `xssentinel-headless` measures. For DVWA
  the headless arm reports the finding as `browser-refuted` with low
  confidence (headless Chromium did not reproduce the dialog in that arm), but
  the independent Playwright check above did; this is a confidence-quality
  observation to track, not a change to ground truth.
- A JSON echo of a stored payload (`js-unsafe-product-json-control`) must not
  be reported as XSS; it is a false-positive control, not a missed finding.
- OWASP ZAP could not be executed on this host (registry/network constraints
  above). dalfox/nuclei are **open-source comparators**, not ZAP and not a
  commercial baseline; no row here implies superiority over Burp/Acunetix.
- Multi-role authentication was checked separately (DVWA admin + `gordonb`,
  Juice admin + a locally registered customer): low-privilege write ->
  high-privilege view works on both; the same payload fires in both DVWA
  sessions, while Juice customer session can read `/api/Users` JSON but the
  `/#/administration` route does not render it (no dialog). Those probes are
  evidence, not scored cases.
- This is a **smoke corpus** for regression, not a quantitative benchmark. The
  194-case matrix and XSSMaze remain the quantitative arms.
