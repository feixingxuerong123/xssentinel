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
`Requires-Python >=3.10` for every fixed release.  The blocker was the
**Python floor**, not a stale pin: `requires-python = ">=3.9"` made the
fixed versions uninstallable on a supported interpreter (until Phase 328d).

Compatibility under 3.12 + the fixed versions: **71 passed** —
`test_egress_guard.py` (aiohttp cookie/redirect behavior),
`test_mcp_server.py` (subprocess stdio e2e), `test_phase196_api_gate.py`
(Flask 3.1.3 / Werkzeug 3.1.9), both Phase 328 suites and the existing
sitemap tests.

Raw artifacts (ignored): `dev/_pip_audit_fresh.json` (3.9),
`dev/_pip_audit_312.json` (3.12).

## Decision (2026-10-26): Python floor raised to >=3.10 (Phase 328d)

Applied:

* `requires-python = ">=3.10"`; the 3.9 classifier is removed; README
  badges/notes and SECURITY are updated.  3.9 is no longer supported.
* Runtime floors are the lowest fixed releases: `requests>=2.33.0`,
  `urllib3>=2.8.0`, `soupsieve>=2.9.0`, `aiohttp>=3.14.4`,
  `Flask>=3.1.3`, `Werkzeug>=3.1.9`.
* The dev `pytest` floor is deliberately left at `>=7.0`: the advisory is
  dev-only, a fresh install already resolves the fixed release, and a full
  pytest-9 compatibility round is not claimed here.
* CI gains a `min-python` job (Python 3.10 install + CLI + egress/MCP/API/
  sitemap smoke); the main job stays on 3.11.

Verification under Python 3.12 + the new floors: **228 passed** — egress,
MCP subprocess e2e, `test_p27_api.py` + AI report, both Phase 328 suites,
sitemap, async decode/layers/headless/param coverage.  `pip check` clean,
`pip-audit` **0 direct advisories**.  Two additional rulers: a 3.9 install
is rejected by pip (`3.9.4 not in '>=3.10'`), and the built wheel's
`METADATA` carries `Requires-Python: >=3.10` plus all six runtime floors.

## Remaining verification

1. ✅ (2026-11-01) The full suites have since run under the floors on CI:
   the push `tests` job (full file-by-file gate, 3.11) is green on
   2026-10-29 / 10-31 / 11-01 (runs 1073ec4 → 793535b), and `benchmark-full`
   (full 194-case matrix) is green in the 2026-11-01 nightly. The quick
   strict slice record under the floors (Phase 328d) is kept below.
2. ✅ Flipped 2026-11-01: the main CI job has passed on 3.10 (min-python)
   and 3.11 (tests) with these floors on every push since Phase 328d, and
   two fresh-install audits report 0 advisories (2026-10-26; 2026-11-01
   re-run on the declared venv, artifact in the gitignored local archive).
   The nightly step is now blocking with one retry for OSV transport
   blips; a real advisory fails both attempts and stays red.
3. Python 3.9 is intentionally unsupported; do not reintroduce a 3.9 path
   that silently resolves the vulnerable releases.

`dev/_pip_audit_p328b.json` is the raw local artifact (ignored, not
committed); this document is the durable record.

## 2026-11-04: first real blocking finding — the runner's setuptools

手动 `workflow_dispatch` run `41817920644` (@`dc5ad1f`) 的 `dependency-audit`
**红了**:日志两次 `Found 3 known vulnerabilities in 1 package`,重试无效 ⇒
真实告警,不是 OSV 传输抖动。artifact `pip-audit.json` 定位:

| 包 | 版本 | 告警 | 修复版本 |
|---|---|---|---|
| setuptools(runner 预装,非项目声明依赖) | 79.0.1 | PYSEC-2026-3447 / CVE-2026-59890 / GHSA-h35f-9h28-mq5c(两条同源记录) | 83.0.0 |
| 同上 | 79.0.1 | GHSA-xmj3-9gf7-h52w(Windows wheel 安装路径可写出目标目录) | 84.1.0 |

**归因**:`pip-audit` 默认审整个已安装环境,`setup-python` 的 ubuntu-latest
镜像自带 setuptools 79.0.1。它不是 `requirements.txt` / `pyproject.toml` 的
运行时依赖,但 `[build-system] requires = ["setuptools>=77"]` 确实把 setuptools
当构建后端 —— 所以这个环境里的漏洞是真实的,不是量具误报,不能用「不是我们的依赖」
一句话打发。

**处置(择一,选了前者)**:

- ✅ **升级工具链**:`dependency-audit` job 在所有 install 之后
  `pip install -U "setuptools>=84.1.0"`,让 pip-audit 看到的最终环境无已知告警。
  不动 `[build-system] requires` —— 抬构建下限按版本策略是 BREAKING(major),
  且 pip 的 build isolation 本就解析到最新版本,与本红无关。
- ❌ 给 `pip-audit` 加 `--ignore-vuln` 或把 runner 预装包排除出审计面:等于
  引入豁免名单、缩窄门,下一次工具链真出漏洞会被藏起来(与 Phase 207
  「不引入豁免名单」同族)。

**口径**:上文 2026-10-26 / 11-01 的「0 advisories」是带日期的历史记录,按规矩
保留不改 —— 它们量的是**声明的 venv**,不是 ubuntu-latest runner 的完整环境。
自本次起 CI 的 audit job 审计「升级工具链后的整个环境」,两把尺子不同,引用时
必须带日期与范围。守卫 `tests/test_dependency_audit_setuptools.py` 钉住升级
步骤、版本下限、审计命令未被缩窄、job 触发条件,以及文档与 workflow 同源。
