# Dependency audit baseline (Phase 328c, 2026-10-26)

This is a **measurement record**, not an upgrade.  It exists because the
supply-chain direction was previously dismissed as "no direct overlap with
this repo"; the local environment says otherwise, and an unmeasured claim
is not a decision.

## What was measured

```bash
# Local Python 3.9 environment, project installed editable.
python -m pip_audit --format json -o dev/_pip_audit_p328b.json
```

* `pip-audit 2.9.0`, 258 installed distributions audited.
* Filtering to this project's direct/optional dependency closure yields
  **43 advisories across 7 packages**.
* `pip check` reports four unrelated global-environment conflicts
  (django/httpcore/langsmith/py7zr); none is a project dependency and none
  is counted below.

| Package | Installed | Fixed in | Scope | Representative issue |
|---|---|---|---|---|
| aiohttp | 3.13.3 | 3.13.4 / 3.14.4 | `async` engine | 32 advisories. Cross-origin redirect keeps cookies / `cookies=` reaches the next origin (PYSEC-2026-2100, -2105) — the same threat class the Phase 189 egress guard addresses manually. Also parser hardening, decompression and resource-exhaustion fixes. |
| urllib3 | 2.6.3 | 2.7.0 / 2.8.0 | requests transport | 5 advisories. Streaming API can decompress the whole body, cross-origin redirect auth via `ProxyManager`, proxy TLS settings. |
| requests | 2.32.5 | 2.33.0 | core | 1 advisory: predictable temp filename in `extract_zipped_paths()` (not used by the scan path). |
| soupsieve | 2.8.4 | 2.9.0 | BeautifulSoup CSS selectors | 2 advisories: hand-written selector regexes can backtrack on hostile selectors. |
| Flask | 2.2.5 | 3.1.3 | `--serve` / `--use-flask` | 1 advisory: missing `Vary: Cookie` when the session is accessed. |
| werkzeug | 3.1.8 | 3.1.9 | `--serve` | 1 advisory: `safe_join` accepts Windows device names with an empty ADS marker. |
| pytest | 8.4.2 | 9.0.3 | dev only | 1 advisory: predictable `/tmp/pytest-of-{user}` directories on UNIX. |

The direct dependencies `beautifulsoup4` and `lxml` themselves produced no
advisories in this run; soupsieve is pulled in by BeautifulSoup.

## Decision (Phase 328c)

**No blind bump.**  The local interpreter is a shared, long-lived global
3.9 environment with 258 distributions; mutating it would not test the
declared project, and two upgrades are known to touch measured behavior:

* **aiohttp 3.13.3 → 3.14.x**: the Phase 209/306 brotli-decoder workaround
  (`safe_accept_encoding`) and the Phase 189 egress/cookie-jar guard both
  have tests that must be re-measured against the new parser/redirect
  behavior.  A dependency bump is a behavioral change here, not a
  version-string change.
* **Flask 2.2.5 → 3.1.3 / werkzeug 3.1.9**: Phase 326 already recorded the
  `werkzeug.__version__` / Flask-compat trap; the API front ends need their
  own round-trip run after the upgrade.

## Fresh-install control (measured 2026-10-26)

The first audit ran in the long-lived global 3.9 environment.  Two clean
rooms separate "old local environment" from "the project's declared range":

| Environment | Resolved (key packages) | `pip-audit` direct |
|---|---|---|
| Python 3.9, fresh venv, `pip install -e ".[dev,async,ast,api]"` | aiohttp 3.13.5, requests 2.32.5, urllib3 2.6.3, soupsieve 2.8.4, Flask 3.1.3, Werkzeug 3.1.9 | **31 advisories / 5 packages** |
| Python 3.12, fresh venv, same command | aiohttp 3.14.5, requests 2.34.2, urllib3 2.8.0, soupsieve 3.0.4, Flask 3.1.3, Werkzeug 3.1.9 | **0 advisories** |

`pip install --dry-run requests==2.33.0` (likewise urllib3 2.8.0,
soupsieve 2.9.0, aiohttp 3.14.4) on Python 3.9 reports
`Requires-Python >=3.10` for every fixed release.  The blocker is the
**Python floor**, not a stale pin: `requires-python = ">=3.9"` makes the
fixed versions uninstallable on a supported interpreter.

Compatibility under 3.12 + the fixed versions: **71 passed** —
`test_egress_guard.py` (aiohttp cookie/redirect behavior),
`test_mcp_server.py` (subprocess stdio e2e), `test_phase196_api_gate.py`
(Flask 3.1.3 / Werkzeug 3.1.9), both Phase 328 suites and the existing
sitemap tests.

Raw artifacts (ignored): `dev/_pip_audit_fresh.json` (3.9),
`dev/_pip_audit_312.json` (3.12).

## Python floor decision (pending operator)

The project still declares `requires-python = ">=3.9"` and its classifiers
list 3.9.  The measured options are:

* **Raise to `>=3.10`** (recommended): fixed dependency versions become
  installable; Python 3.9 is already EOL (2025-10).  Requires updating
  classifiers, README, and re-running the CI gate on 3.11.
* **Raise to `>=3.11`** (matches the CI interpreter): same benefit, but
  drops 3.10 as well.
* **Keep 3.9**: no breaking change, but 3.9 installs remain exposed.  The
  README/SECURITY warning added in Phase 328c is the minimum honest
  position; the audit job must stay report-only for 3.9.

No `pyproject.toml` change is made until this decision.  The CI job runs
on 3.11, where a fresh install audits clean today.

## Next round (planned, not done)

1. Decide the Python floor (above).
2. If raised: update `requires-python`, classifiers, README; add direct
   constraints for `requests>=2.33.0`, `urllib3>=2.8.0`,
   `aiohttp>=3.14.4`, `Flask>=3.1.3`, `soupsieve>=2.9.0` (and the dev
   `pytest>=9.0.3` floor).
3. Re-run: `test_egress_guard.py`, the async transport/budget suites,
   `test_p27_api.py`, `test_phase196_api_gate.py`, MCP suites, and
   `python -m xssentinel --self-test`; then the strict 64-case slice.
4. Only if all green: regenerate the audit artifact and flip the nightly
   audit job from non-blocking to blocking.

`dev/_pip_audit_p328b.json` is the raw local artifact (ignored, not
committed); this document is the durable record.
