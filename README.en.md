# XSSentinel — a comprehensive XSS detection framework

![CI](https://github.com/feixingxuerong123/xssentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

> A multi-layer, extensible XSS scanner: context-aware reflected injection +
> adaptive WAF evasion + DOM taint analysis + (optional) real headless-browser
> confirmation.

English | [中文](README.md)

---

## ⚠️ Positioning and honesty disclaimer (read this first)

Commercial tools (Acunetix, Burp Suite Pro, Netsparker) are maintained by large
teams and cover crawling and rule sets no open-source tool matches. **No OSS
tool "beats them all"** — it is a moving target.

XSSentinel targets a different claim: **the most complete detection surface and
the cleanest, most extensible architecture among OSS/self-built tools.** Every
layer is replaceable on its own. Highlights:

- **6-layer pipeline**: reflected → WAF evasion → DOM taint → stored → blind
  (OOB) → headless confirmation. Most tools stop after one or two layers.
- **Context-aware**: classifies the reflection into 20+ contexts (HTML body,
  attribute, script string, event handler, `javascript:` URI, SVG, MathML,
  CDATA, template `{{}}`, meta-refresh, HTML comment…) and picks the payload
  per context.
- **Reflection-profile-driven** (DalFox-style sandwich probe): which special
  characters survive — raw / stripped / encoded — feeds payload ordering.
- **Generative payloads** (XSStrike-style): builds payloads on the fly from
  surviving characters (e.g. tagged-template `alert\`1\`` when parens are
  filtered).
- **WAF-adaptive bypass**: 28 transform/encoding families from
  `core/transform.py` `REGISTRY`.
- **DOM XSS**: static taint analysis (sources → sinks) plus optional JS AST
  data-flow (`esprima`, degrades to regex), plus **real headless-browser
  confirmation** (Playwright sink instrumentation with a unique marker; only
  execution in a real browser is *confirmed*, reachability is reported
  separately and never as an XSS).
- **Stored XSS**: inject, re-fetch the display page, confirm persistence.
- **Blind XSS (OOB)**: unique-token callbacks; `--oob self` (self-hosted
  listener, offline testable) or `--oob interactsh`.
- **CSP nonce-leak exploitation chain**: extracts the leaked nonce from the
  page and builds a same-nonce `<script>` — no competitor implements this.
- **Scenario DSL** (Nuclei-style multi-step flows), SQLi error-signature quick
  check, outdated-JS detection, CORS/XS-Leaks audit, passive proxy with MITM CA,
  HAR / OpenAPI / sitemap / wayback imports, hidden-parameter mining, parameter
  position mutation, HPP, source-map ingestion, and more — see
  [docs/COMPETITORS.md](docs/COMPETITORS.md).
- **MCP server** (stdio + Streamable HTTP): seven core tools for LLM agents,
  plus two modern-era async tools (Phase 377), with argument validation,
  `structuredContent`/`outputSchema`, progress notifications and
  cancellation — see `skills/xssentinel-mcp/SKILL.md`.
- **Eight report formats** (`-f`): HTML / JSON / CSV / SARIF 2.1.0 / JUnit / Markdown + Burp XML / nuclei export.
- **CLI pipeline compatibility (Phase 359)**: `-o -` writes the report to stdout as UTF-8 bytes — one JSON line for a single target, JSON Lines for a batch (`-f json` only) — while every summary, progress line and error goes to stderr, so `... | jq` sees only report frames. `-o reports/scan.json` creates missing parent directories. `--batch` / `--batch-stdin` accept UTF-8 (with or without BOM), UTF-16 (BOM), GB18030/GBK and CRLF, with an honest decode error instead of a traceback. Exit codes: `0` ok, `1` crash, `2` usage/input, `3` incomplete scan ("no findings" is not evidence of absence).
- **CLI compatibility sweep (Phase 360)**: `--version` / `-V` print a single-line version; `--ver` stays an exact alias of `--verbose` rather than becoming ambiguous. `--config` shares the batch decoder (UTF-8 BOM / UTF-16 / GB18030); a broken config returns rc=2 with a clear reason instead of silently becoming an empty config or raising a traceback, and keys such as `format` / `timeout` / `output` now take effect (explicit CLI flags still win — see the Changed entry in the changelog). `-o - -f nuclei` is rejected before any scan (rc=2), and a consumer that closes the pipe early (`... | head`) ends the run cleanly (rc=0) instead of reporting every remaining target as a failed scan. Every human-facing line in all three CLI modules is source-pinned to the `-o -` stream; stdout bytes are unchanged when `-o -` is not used.
- **CLI surface audit (Phase 360 follow-up)**: 29 surface cases and 133 parser flags were each driven through a real CLI subprocess with zero crashes and zero timeouts; all eight report formats produced artefacts. Malformed `--raw-request` files, corrupt `--resume` checkpoints and unusable `--poc-dir` paths now return honest errors instead of tracebacks or a false "scan incomplete" (exit 3); `--ai-timeout` reaches `--ai-check`, and `--self-test` avoids an occupied hard-coded port. This audits **entry-point reachability**, not the semantics of every flag combination (covered by the per-feature suites and the 194-case matrix).
  Every confirmed finding carries a reproducible PoC (curl, URL, self-contained
  HTML page).
- **`-o -` closed across every report entry point (post-Phase 362, 2026-11-06)**: scan, `--diff` and `--verify-fix` share one stdout frame writer; `-` is never treated as a filename, so the CWD no longer receives `-` / `-.json` / `-.csv` (stale 11-05 artefacts were removed; a regression test asserts all three are absent in a scratch CWD).
- **XSSMaze residual FNs (Phase 361–362)**: the 69 FNs were attributed case by case and the actionable ones fixed (whole-segment path replacement, the UTF-7 charset gate, bare attribute-name corpus for bracket-dead pages). The 194-case dual-engine verdicts stayed byte-identical to the baseline and all 27/27 controls remained FP-free — see the changelog.

Use it **only against systems you are authorized to test.**

## Maturity (measured 2026-11-02: **Beta**)

`pyproject.toml` has been `Development Status :: 4 - Beta` since 2026-11-02;
this is not Production/Stable. What the evidence supports: semantic
confirmation on the reflected / DOM / stored paths; the self-built 194-case
matrix at FP0/FN0 on both engines; stored auto-discovery 9/9 on both engines
on the official target (2026-11-03); and the real-world regression set v2.2
(22 cases / 5 apps) at **13 TP / 0 FP / 9 TN**, every case backed by an
official challenge or source plus independent Playwright ground truth.
What it does not: full privilege-role matrices, and **no head-to-head with
commercial tools (Burp Pro / Acunetix) on an independent target** — the
comparisons below are against OSS tools (dalfox / nuclei) only. See
[README.md](README.md) for the full statement.

> **First time?** Start with [docs/QUICKSTART.en.md](docs/QUICKSTART.en.md) —
> three commands, four exit codes, and four environment traps that get results
> misread.

## Quality gates (why this result is believable)

- **Push gate**: a 64-case stratified slice on both engines under `--strict-gate`
  (FP0 / FN0 / ERROR0 required); the slice rotates per ISO week, 49 weeks cover
  the full 194-case matrix (numbers pinned by `tests/test_quick_gate_slice.py`).
- **Full matrix**: the 194-case strict gate on both engines exits 0 —
  sync `TP113/FP0/TN81/FN0` (0 SKIP), async `TP107/FP0/TN75/FN0` (12 SKIP);
  27 control cases give 0 FP on both engines.
- **Full gate**: every `test_*.py` runs file-by-file (`--jobs 4`) with its own
  timeout and one retry (failure evidence survives the run). The current
  reference run is **274/274 files effectively green** — 271 in-gate green
  plus 3 environment-timeout files green on standalone rerun — with
  **69 skips across 18 files (5 whole files contributed nothing)**, 1412 s,
  exit 3; the two counts and the skip count are always reported together.
  Guards such as the architecture line caps and the broad-except ratchet are
  mutation-tested (red → restore → green).
- **Independent target**: the official XSSMaze target + official runner scoring
  three tools on the same cases; artifacts ship with the repo (see below).

How to run: [CONTRIBUTING.md](CONTRIBUTING.md) ("Testing") and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Cross-tool benchmark (same targets, same probes, 2026-10-04)

60 deterministic, stratified cases (`ground truth × context`) run against
identical URLs with identical probe values:

| Tool | Version | TP | FP | TN | FN | ERR | recall | f1 | wall clock |
|---|---|---|---|---|---|---|---|---|---|
| **XSSentinel** | this repo (14/12 budget, same gate) | 35 | 0 | 24 | 1 | 0 | 0.972 | **0.986** | 346 s |
| DalFox | v2.13.0 | 26 | 1 | 22 | 10 | 1 | 0.722 | **0.825** | 1173 s |
| nuclei (dast/xss templates) | v3.9.0 | 26 | 0 | 23 | 10 | 1 | 0.722 | **0.839** | 49 s |

Three caveats, or the table misleads: the targets are still **ours** (the probe
corpus is third-party, the range is not); the single FN is a scoring choice
(XS-Leaks findings are `low` by design and not "detected" at `high/medium`);
**speed is not a one-way advantage** — nuclei finishes 7× faster.

XSSMaze v0.3.0 (official runner, 2026-10-24): server 925/88/0 (R 91.3%,
F1 0.955), client 24/0/0 (F1 1.000), 27 control cases with zero findings.
Replay-corrected 948/65.

Phase 342 (2026-10-30), same official target + official runner, three tools
scored identically: XSSentinel TP944 / FN69 / FP0 (P 1.000, R 0.932, F1 **0.965**,
5741 s), dalfox 757/256/4 (F1 0.853, 4072 s), nuclei 731/282/4 (F1 0.836, 406 s);
control FP: this repo 0, each competitor 4 (all CSP/nonce-protected pages).
Caveats: the dalfox arm is the frozen Go branch v2.13.0 (the current Rust v3 was
not run — its release assets are not fetchable from this host) and ran with
`--skip-headless` (chromedp instability on this host; headless contribution
quantified separately on a sample); the XSSentinel scorecard reuses p341 (zero
detection-surface commits between trees). nuclei remains an order of magnitude
faster (406 s vs 5741 s). Versions, per-arm deviations and per-case data:
[benchmark/results/phase342_xssmaze/](benchmark/results/phase342_xssmaze/p342_meta.json).

### Reference caveats (re-checked 2026-11-08)

[external_validity_20261108.md](benchmark/results/external_validity_20261108.md)
organises every figure above by sample size, tool version, scoring convention and
non-comparable items. Read these before quoting any number in this section:

- **Full run of 2026-11-08 (uncommitted WIP tree, NOT the released 1.4.3):**
  legacy GET-only convention TP 975 / FN 38 / FP 0 (R 96.2%, F1 0.981, 1959.1 s);
  opt-in POST-aware convention TP 987 / FN 26 / FP 0 (R 97.4%, F1 0.987,
  2039.6 s). **0.987 is not a detection improvement** — POST-only endpoints
  finally received their body. The two conventions are not comparable, and
  neither is comparable to the 0.965 / 0.957 figures above. **Decision of
  2026-11-08: GET-only remains the official convention**; POST-aware is an
  opt-in diagnostic convention and rewrites no historical figure.
- **The three snapshots (10-24 / 10-30 / 11-08) do not form a progress curve:**
  different code trees (the current one is uncommitted WIP), mixed Phase 364–371
  changes, different wrapper timeouts (100 s / 30 s / 90 s) and different loopback
  conditions on this host.
- **dalfox results do not extrapolate to its current release**: the compared arm
  is the frozen Go branch v2.13.0; Rust v3 has never been run.
- **Self-authored evidence is not third-party evidence**: the 194-case matrix,
  range3–7 and bWAPP use our own targets and our own answer key; F1 = 1.0 there
  only means "not broken" and must not be shown next to the XSSMaze F1 as two
  perfect scores. FP = 0 on 27 controls says nothing about production
  false-positive rates.
- **Blanks**: zero comparisons against Burp Pro / Acunetix / Netsparker, OWASP
  ZAP BLOCKED/unavailable, no authorised production targets or traffic, and a
  speed gap of roughly one order of magnitude behind nuclei. More lab cases cannot
  fill this layer, and this project makes no claim of beating commercial XSS tools.
- **Timeout artefacts**: intermittent host instability has produced false FNs and
  `partial` scans; every such deviation was re-run and attributed individually.
  Since 2026-11-08 evening `wsl.exe` is blocked by local security policy, so the
  Docker backend cannot start and XSSMaze re-runs are currently impossible.

PortSwigger cheat-sheet corpus coverage (822 vectors; re-run 2026-11-01 against
the 2026-09-30 cheat-sheet snapshot, product: benchmark/results/portswigger_corpus_coverage.json):
the "no user interaction" group is **100%** on events, tags and protocols (gap
zeroed by the Phase 192 corpus additions); the "requires-interaction" group is
73.1% on events (76/104) — reference only, not the main metric. The 15.4%
figure sometimes quoted as a "before" value is the pre-Phase-192 rate of
**all three groups pooled**, a misleading denominator; it is not this group's
historical event coverage.

---

## Detection architecture (6 layers)

```
L1  Reflection  probe today's reflection point -> 20+ contexts -> per-context payloads
L2  WAF bypass  on block -> 28 transform/encoding families -> retry
L3  DOM        static source->sink analysis of page JS
L4  Stored     inject -> re-fetch display page -> confirm persistence
L5  Blind OOB  (optional) unique-token callbacks -> polling -> beacon = confirmed
L6  Headless   (optional) real Chromium: sink instrumentation + marker injection;
                only browser-executed carriers count as confirmed DOM XSS

Every layer ends in semantic confirmation: a unique token must land in a
genuinely executable position (html.escape'd reflections are rejected).
```

Discovery: BFS crawler with `--scope`/`--crawl-depth`, SPA hash-route discovery
from app bundles, hidden-parameter mining, dedup by `(type, url, param,
context)`, and reproducible PoCs per confirmed finding.

---

## Install

```bash
cd xssentinel
python -m venv .venv && .venv\Scripts\activate     # Windows
#   or: source .venv/bin/activate                  # Linux/macOS
pip install -e .                                   # deps: requests, beautifulsoup4
```

Optional headless confirmation (L6 and `--discover`):

```bash
pip install playwright && playwright install chromium
```

Optional JS AST data-flow: `pip install xssentinel[ast]`.

> **Python 3.10+ required**: 3.9 is EOL and the fixed releases of
> requests / urllib3 / aiohttp / soupsieve all require Python >=3.10; a fresh
> 3.9 install still resolves versions with known advisories (measured in
> [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md)). 3.9 support was
> dropped in Phase 328d (CI uses 3.11, with a 3.10 floor smoke job).

> **Release status (2026-11-04)**: this project is **not published on PyPI**
> yet (`pypi.org/project/xssentinel` returns 404) -- install from source as
> shown above. `.github/workflows/pypi-publish.yml` is ready, but the repo
> owner must finish the one-time Trusted Publisher setup on pypi.org before a
> `v*` tag push can upload anything (until then the publish job fails with
> 403). See the maturity statement above for the Beta status and limits.

---

## Quick start

```bash
# A GET parameter (auto-extracted from the URL's ?q=)
python -m xssentinel -u "https://example.com/search?q=test" -o report.html

# POST form, auth headers, proxy
python -m xssentinel -u "https://example.com/comment" -m POST -d "name=x&bio=y"
python -m xssentinel -u "https://example.com/p" -H "Authorization: Bearer <TOKEN>" -b "session=yyy"

# Crawl (depth 2) / checkpoint & resume
python -m xssentinel -u "https://example.com" -c
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json --resume

# Real-browser confirmation (needs playwright)
python -m xssentinel -u "https://example.com/search?q=test" --headless

# Report formats (`-f`: html,json,csv,sarif,junit,markdown,burp,nuclei)
python -m xssentinel -u "https://example.com/search?q=test" -f sarif -o report.sarif

# Stored XSS: explicit write/read pair. On the sync engine, viewer discovery
# is on by default (--no-stored-auto disables it); --stored-inject implies off.
python -m xssentinel -u "https://example.com/p" --stored-inject https://example.com/store --stored-view https://example.com/view

# Blind XSS (self-hosted listener / public interactsh)
python -m xssentinel -u "https://example.com/search?q=test" --oob self

# SQLi error-signature quick check / outdated JS libraries
python -m xssentinel -u "https://example.com/p" --sqli-check
python -m xssentinel -u "https://example.com/p" --check-outdated-js

# Passive proxy: browser traffic flows into the pipeline (xray-style)
python -m xssentinel --passive --port 8080
#   HTTP proxy for the browser; HTTPS CONNECT tunnel by default,
#   --mitm-ca mitm/ca.pem adds HTTPS interception (install ca-cert.pem first)

# Batch: file or stdin pipe, one report per target into -o DIR
python -m xssentinel --batch urls.txt -o reports/
python -m xssentinel --batch-stdin -o reports/

# HAR / OpenAPI / sitemap / wayback imports
python -m xssentinel --har capture.har -o reports/
python -m xssentinel --openapi spec.json -o reports/
python -m xssentinel --sitemap https://target.com/sitemap.xml -o reports/
python -m xssentinel --wayback target.com -o reports/ -f json
```

`--scan-policy {quick,normal,deep}` switches the budget profile; explicit flags
always win over the preset.

---

## MCP server for LLM agents

**stdio** (spawned by the client):

```bash
python -m xssentinel --mcp
```

Seven core tools cover recon → scan → adjust-and-retry (modern `2026-07-28`
clients additionally get `xssentinel_scan_async` / `xssentinel_scan_status`;
a legacy `tools/list` stays byte-identical with the seven below):
`xssentinel_discover` (render once, harvest SPA fields/API endpoints/hash
routes), `xssentinel_profile` (one-request reflection triage), `xssentinel_param_mine`
(hidden parameters), `xssentinel_csp_analyze` (CSP posture per delivery family),
`xssentinel_scan` (full scan), `xssentinel_verify` (replay ONE payload through
the same judge — the agent's retry loop), `xssentinel_propose` (LLM proposes,
the token oracle decides).

**Streamable HTTP** (mounted on the REST API, for URL-based agent platforms):

```bash
python -m xssentinel --serve --host 127.0.0.1 --port 8080    # add --api-key in production
# MCP client: url = http://127.0.0.1:8080/mcp  (+ X-API-Key header when configured)
```

Protocol behavior: single or batched JSON-RPC arrays; notification-only batches
→ 202 with no body; malformed JSON → JSON-RPC `-32700` (not HTTP 400);
GET/DELETE `/mcp` → 405 (no SSE upgrade, no session to terminate). Same auth
and same-origin gate as the REST API.

**Dual-era protocol support (Phase 358)** — the current MCP revision
`2026-07-28` removed the `initialize` handshake and requires
`server/discover`. This server answers both eras: legacy clients keep their
byte-for-byte `initialize` responses; modern clients declare
`params._meta.io.modelcontextprotocol/protocolVersion` and get `resultType`,
`_meta.serverInfo` and cache hints, with `-32022` plus a `supported` list for
unknown versions. On Streamable HTTP, a mismatched `MCP-Protocol-Version` or
`Mcp-Method` header returns 400 `-32020`, an unknown modern method returns
404 `-32601`; missing headers are tolerated for CLIs that omit them. stdio is
a UTF-8 byte channel, so a Windows cp936/gbk console can no longer break a
frame containing non-ASCII target data. MRTR, `subscriptions/listen` and SSE
streams are intentionally out of scope.

**Contracts**: `tools/call` arguments are validated against each tool's
inputSchema — unknown keys are rejected with the accepted-key list (never
silently dropped: a misspelled `cookie` used to run an unauthenticated scan
that then reported "clean"), REST spellings (`target`/`cookie`/`header`/
`body`/`parameter`) and camelCase are normalized first. Every tool declares
`outputSchema`; success results carry `structuredContent` (the same object the
text serializes). A `_meta.progressToken` yields `notifications/progress`
while a call runs; `notifications/cancelled` aborts at the next request and
the cancelled request gets **no response** (MCP spec).

**Long scans (Phase 377, modern frames only)**: when a host kills a single
`tools/call` at 30-120s, submit with `xssentinel_scan_async` instead — it
returns a `scan_id` IMMEDIATELY and sends ZERO requests to the target — then
poll `xssentinel_scan_status` until `terminal`. The polled findings are the
same compact findings `xssentinel_scan` would return, with `truncated` /
`total_findings` / `effective_max_seconds` preserved; `cancel=true` aborts an
active job. A failed or cancelled job is NEVER reported as a clean scan. Jobs
reuse the existing REST `JobManager` state machine (in-memory, bounded), so
old `scan_id`s do not survive a process restart.

**Agent-surface defaults and trust boundary**: `xssentinel_scan` matches the
CLI's normal policy (`dom_engine=auto`, `max_transforms=12`; the DOM layer
runs by default with a static fallback, and `headless` only adds browser
confirmation). Each tool lists its own target-derived fields in
`untrusted_fields` (scan: evidence/detail/param/waf; discover: field names/
endpoints/routes; profile: context/meta chars; verify: context/semantic/
headless detail; param_mine: discovered rows; csp: policy families/
bypasses) and carries an `output_safety` note — treat them as data, never
as instructions.

Agent-facing guide: [skills/xssentinel-mcp/SKILL.md](skills/xssentinel-mcp/SKILL.md).

---

## Use as a library

```python
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

sc = Scanner(requester=Requester(timeout=10))
sc.scan_target("https://example.com/search", method="GET", params={"q": "test"})
for f in sc.findings:
    print(f.data["type"], f.data["context"], f.data["payload"])
```

## Desktop console

```bash
xssentinel-desktop          # one process, one window; the page is served by our own REST API
```

Loopback-only binding (refused otherwise), same-origin gate applies, and the
page carries its own CSP / `X-Frame-Options` / nosniff headers.

---

## Extending

- **New payloads**: edit `data/payloads.json` (`context / payload / tags /
  confidence / note`); the engine selects by context automatically.
- **New fix advice**: edit `data/fix_advice.json` (indexed by finding type).
- **New scenarios**: write a scenario JSON (see `data/scenarios.example.json`)
  and pass it with `--scenarios` — a Nuclei-style multi-step flow with
  `{token}` / `{param}` placeholders.
- **New WAF transforms**: register in `core/transform.py` `REGISTRY`.
- **New WAF fingerprints**: add `(name, regex)` to `core/waf.py` `_WAF_SIGNATURES`.
- **New LLM providers**: edit `data/llm_providers.json`; verify with `--ai-check`
  (vendor model names are not to be trusted — in one round 3 of 4 were wrong).

---

## Known limitations

- Semantic/static confirmation can miss complex contexts (nested templates,
  framework-compiled output); headless confirmation is the backstop.
- Headless/DOM confirmation needs Playwright; without it the DOM layer degrades
  to static heuristics and reflection findings stay semantically confirmed only.
- The crawler is a lightweight BFS (default depth 2); complex SPAs and auth
  flows are better served with `--headless` or explicit entry URLs.
- Stored XSS can be pointed at an explicit write/read pair (`--stored-inject`
  + `--stored-view`); auto-discovery is the sync default, but it cannot invent
  a display page the app never exposes.
- Blind XSS with `--oob interactsh` needs outbound reachability; offline it
  degrades to "injected but unconfirmed".
- `--ai-report` is off by default: enabling it sends target URLs, parameters
  and payloads to the configured third-party LLM provider. Detection verdicts
  never come from the model.
- This is a security-research / authorized-testing tool. Do not use it against
  targets you are not authorized to test.

---

## License

MIT — see [LICENSE](LICENSE).
