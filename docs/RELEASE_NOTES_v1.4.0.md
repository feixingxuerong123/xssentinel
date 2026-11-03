# Release notes — XSSentinel v1.4.0 (2026-11-04)

> 仓库归属者发布步骤（发布前无需改本文件）：
>
> ```
> gh release create v1.4.0 --title "XSSentinel 1.4.0" --notes-file docs/RELEASE_NOTES_v1.4.0.md --latest
> ```
>
> （如未装 gh CLI：GitHub 网页 → Releases → Draft a new release → 选 tag v1.4.0 →
> 粘贴下方正文。）

---

## Highlights

XSSentinel is a multi-layer XSS detection framework: context-aware reflected
injection, adaptive WAF evasion, DOM taint analysis with real-browser execution
confirmation, stored & second-order flows, blind-XSS (OOB) auto-confirmation,
CSP nonce-leak exploitation chain, scenario DSL, passive proxy, and a
benchmark/range suite that gates every push.

**1.4.0** (2026-11-04) — stored auto-discovery & marker-form round (Phases 345–356):

- **Stored auto-discovery on by default (Phase 352)** — the scanner now finds
  stored-XSS write/read pairs on its own (own Mixin: `scanner_stored_auto.py` +
  `stored_discovery.py`): write-form probing, re-read with fingerprint
  differencing, per-view polling only when the view actually changed. Official
  targets: **9/9 sync, 9/9 async, 0 FP**; explicit `--stored-inject` runs skip
  the redundant auto pass; a dead target trips the circuit breaker instead of
  burning the request budget.
- **Marker-form fan-out (Phase 356)** — one plain probe per quoting shape
  before the transform ladder: a PHP-`addslashes`-style filter kills the
  single-quoted form (`alert('tok')` → syntax error) but not the bare /
  double-quoted / backtick forms. The unquoted form carries a sha1-derived
  10-digit numeric alias instead of the token; a one-probe
  `_detect_quote_escaping` check buys the fan-out only where it can matter.
  `XSS_MARKER_FORMS=0` is the A/B legacy path.
- **DOM static layer precision (Phase 354)** — AST-first (esprima cross-statement
  taint chains), regex fallback; five real-framework shapes (`document.title=`,
  `aria-label`, `.attr('title')`, `.val()`, `appendChild`) no longer report,
  true sinks unchanged, `low` never enters the report. Stated limits: computed
  property names, cross-statement object identity, external bundles → browser
  arm.
- **Real-world regression set v2.2** — 22 cases / 5 apps (Juice Shop anon+
  unsafe, DVWA, bWAPP, self-hosted lab), each with official challenge /
  source / `bugs.txt` grounding and an independent Playwright ground truth.
  Same-target comparison: xssentinel **13 TP / 0 FP / 9 TN (recall 1.000)**,
  dalfox 0.571, nuclei 0.500 — an open-source comparison, not a commercial
  baseline (none available on this machine).
- **Maturity: Beta** — `pyproject.toml` downgraded from `Production/Stable`
  with the measured justification in-file; README now states
  capable / not-yet / out-of-scope as measured, not aspired.
- **Auth-session header canary fix (Phase 355)** — the transport layer's
  all-name header canary no longer lists `Cookie` as an injection surface on
  authenticated sessions (it dirtied the session it was riding on).

## Verification (same gates as every push)

- 194-case in-repo matrix, both engines: FP0 / FN0, f1 = 1.0
- Quick strict 64-case slice, both engines: F1 = 1.0 (re-verified 2026-11-03/04)
- 27 official XSSMaze control cases: 0 FP, both engines
- Real-world v2.2: 13 TP / 0 FP / 9 TN
- Full batched file-by-file gate: 274 files green (271 in-gate + 3
  environment-timeout files green standalone; 2026-11-04 night on a
  degraded machine — evidence chain and protocol in AGENTS.md)
- `xssentinel selftest`: ALL CHECKS PASSED (92 checks incl. real-browser
  L6 confirmation and blind-XSS callback; 2026-11-04)

## Install

```bash
git clone https://github.com/feixingxuerong123/xssentinel
cd xssentinel
pip install -e .                       # core (Python >= 3.10)
pip install playwright && playwright install chromium   # optional: L6 browser confirmation
```

Docker (built by CI from this tag):

```bash
docker run --rm ghcr.io/feixingxuerong123/xssentinel:1.4.0 scan -u "https://host/search?q=probe" -f sarif -o /scans/report.sarif -v "$PWD:/scans"
```

PyPI: publishing workflow ships with this tag; after the one-time Trusted
Publisher setup, `pip install xssentinel` will follow.

## Scope & honesty

Use only against systems you are authorized to test. The project is
classified **Beta**: single-target / small-batch authorized XSS testing and
CI regression are in scope; large-scale asset sweeps, multi-role
login workflows beyond the measured matrix, and any "zero missed findings"
promise are not. Speed and coverage comparisons vs nuclei/dalfox (and the
remaining XSSMaze FN classes) are documented in
[README.md](../README.md) — read the caveats next to the tables, not just
the tables.

Full changelog: [CHANGELOG.md](../CHANGELOG.md)
