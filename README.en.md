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
- **WAF-adaptive bypass**: 23 transform/encoding families from
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
- **MCP server** (stdio + Streamable HTTP): seven tools for LLM agents with
  argument validation, `structuredContent`/`outputSchema`, progress
  notifications and cancellation — see `skills/xssentinel-mcp/SKILL.md`.
- **Six report formats**: HTML / JSON / CSV / SARIF 2.1.0 / JUnit / Markdown.
  Every confirmed finding carries a reproducible PoC (curl, URL, self-contained
  HTML page).

Use it **only against systems you are authorized to test.**

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

PortSwigger cheat-sheet corpus coverage (822 vectors): the "no user
interaction" group is **100%** on events, tags and protocols; the
"requires-interaction" group is only 15.4% — expected, since most of that group
needs a user gesture and is not counted as the main metric.

---

## Detection architecture (6 layers)

```
L1  Reflection  probe today's reflection point -> 20+ contexts -> per-context payloads
L2  WAF bypass  on block -> 23 transform/encoding families -> retry
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

Optional headless confirmation (L4/L6 and `--discover`):

```bash
pip install playwright && playwright install chromium
```

Optional JS AST data-flow: `pip install xssentinel[ast]`.

> **Python 3.10+ required**: 3.9 is EOL and the fixed releases of
> requests / urllib3 / aiohttp / soupsieve all require Python >=3.10; a fresh
> 3.9 install still resolves versions with known advisories (measured in
> [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md)). 3.9 support was
> dropped in Phase 328d (CI uses 3.11, with a 3.10 floor smoke job).

---

## Quick start

```bash
# A GET parameter (auto-extracted from the URL's ?q=)
python -m xssentinel -u "https://example.com/search?q=test" -o report.html

# POST form, auth headers, proxy
python -m xssentinel -u "https://example.com/comment" -m POST -d "name=x&bio=y"
python -m xssentinel -u "https://example.com/p" -H "Authorization: Bearer X" -b "session=yyy"

# Crawl (depth 2) / checkpoint & resume
python -m xssentinel -u "https://example.com" -c
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json --resume

# Real-browser confirmation (needs playwright)
python -m xssentinel -u "https://example.com/search?q=test" --headless

# Six report formats
python -m xssentinel -u "https://example.com/search?q=test" -f sarif -o report.sarif

# Stored XSS: inject at /store, confirm on /view
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

Seven tools cover recon → scan → adjust-and-retry:
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

**Contracts**: `tools/call` arguments are validated against each tool's
inputSchema — unknown keys are rejected with the accepted-key list (never
silently dropped: a misspelled `cookie` used to run an unauthenticated scan
that then reported "clean"), REST spellings (`target`/`cookie`/`header`/
`body`/`parameter`) and camelCase are normalized first. Every tool declares
`outputSchema`; success results carry `structuredContent` (the same object the
text serializes). A `_meta.progressToken` yields `notifications/progress`
while a call runs; `notifications/cancelled` aborts at the next request and
the cancelled request gets **no response** (MCP spec).

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
- Stored XSS needs a display page (`--stored-inject` + `--stored-view`).
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
