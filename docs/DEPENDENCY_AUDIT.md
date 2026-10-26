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

## Next round (planned, not done)

1. Create an **isolated venv** (not the shared global 3.9 install).
2. Install the fixed versions:
   `requests>=2.33.0`, `urllib3>=2.8.0`, `aiohttp>=3.14.4`,
   `Flask>=3.1.3`, `werkzeug>=3.1.9`, `soupsieve>=2.9.0`,
   `pytest>=9.0.3` (dev only) — after confirming each supports the
   project's Python floor.
3. Re-run: `test_egress_guard.py`, the async transport/budget suites,
   `test_p27_api.py`, `test_phase196_api_gate.py`, MCP suites, and
   `python -m xssentinel --self-test`; then the strict 64-case slice.
4. Only if all green: raise the floors in `pyproject.toml`, regenerate the
   audit artifact, and flip the nightly audit job from non-blocking to
   blocking.

`dev/_pip_audit_p328b.json` is the raw local artifact (ignored, not
committed); this document is the durable record.
