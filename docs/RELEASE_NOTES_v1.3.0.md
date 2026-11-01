# Release notes — XSSentinel v1.3.0 (2026-10-31)

> 仓库归属者发布步骤（发布前无需改本文件）：
>
> ```
> gh release create v1.3.0 --title "XSSentinel 1.3.0" --notes-file docs/RELEASE_NOTES_v1.3.0.md --latest
> ```
>
> （如未装 gh CLI：GitHub 网页 → Releases → Draft a new release → 选 tag v1.3.0 →
> 粘贴下方正文。）

---

## Highlights

XSSentinel is a multi-layer XSS detection framework: context-aware reflected
injection, adaptive WAF evasion, DOM taint analysis with real-browser execution
confirmation, stored & second-order flows, blind-XSS (OOB) auto-confirmation,
CSP nonce-leak exploitation chain, scenario DSL, passive proxy, and a
benchmark/range suite that gates every push.

**1.3.0** (2026-10-31) — engine attribution & CLI readability round (Phases 340–344):

- **Subcommands with layered `--help` (Phase 344)** — `xssentinel serve | selftest | mcp | scan`.
  Pure syntax sugar over the existing flags: flat invocations are byte-identical,
  each mode keeps a single code path, and per-mode `--help` fits on one screen
  (the full scan help keeps its built-at-runtime argument count and a navigation
  header).
- **Engine attribution in every artifact (Phase 343)** — reports always carry
  `engine` (plus `engine_fallback_reason` when `--async` fell back to sync), the
  HTML report shows an `ENGINE FALLBACK` banner, and `--require-async` exits 3
  *before any traffic* when aiohttp is missing — a pipeline can no longer claim
  async it never ran.
- **Rotating push-gate slice (Phase 343)** — the 64-case strict slice rotates by
  ISO week (`--quick-offset`); 49 rotations cover the full 194-case matrix, so a
  regression outside the fixed slice surfaces within days, not never.
- **`--help` navigation header (Phase 343)** — 157 flags / 650 lines now start
  with a six-line "find by workflow" index.
- **Hosted CI hardened (Phase 340)** — batched runner no longer scores module
  skips as failures, failure logs survive the run as artifacts, drills split
  into their own parallel job; full suite green on hosted runners.
- **Network-free DOM carrier (Phase 341)** — `<svg onload=…>` joins the carrier
  shapes, removing an HTTP round-trip that could silently downgrade
  browser-confirmed DOM findings on slow targets; external XSSMaze scorecard
  unchanged (944/69/0).

## Verification (same gates as every push)

- Full 194-case matrix, both engines: FP0 / FN0, f1 = 1.0
- Quick strict slice, both engines: exit 0
- Full batched file-by-file gate: 258/258 files green
- `xssentinel selftest`: ALL CHECKS PASSED

## Install

```bash
git clone https://github.com/feixingxuerong123/xssentinel
cd xssentinel
pip install -e .                       # core (Python >= 3.10)
pip install playwright && playwright install chromium   # optional: L6 browser confirmation
```

Docker (built by CI from this tag):

```bash
docker run --rm ghcr.io/feixingxuerong123/xssentinel:1.3.0 scan -u "https://host/search?q=probe" -f sarif -o /scans/report.sarif -v "$PWD:/scans"
```

PyPI: publishing workflow ships with this tag; after the one-time Trusted
Publisher setup, `pip install xssentinel` will follow.

## Scope & honesty

Use only against systems you are authorized to test. The project's own
positioning and its measured limits (speed vs nuclei, dalfox comparison
versions, remaining XSSMaze FN classes) are documented in
[README.md](../README.md#外部参照同类开源扫描器同靶跑分2026-10-04) — read the
caveats next to the tables, not just the tables.

Full changelog: [CHANGELOG.md](../CHANGELOG.md)
