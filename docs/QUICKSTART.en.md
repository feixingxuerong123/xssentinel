# XSSentinel — Quickstart

中文版:[docs/QUICKSTART.md](QUICKSTART.md) | English: this file

This document answers exactly one question: **how to get, within five minutes, a
result I can judge as real or false**.
The full capability list is in [README](../README.en.md); detection principles are
in the "Detection architecture" section —
those are reference material, not a getting-started path.

---

## 1. Install

```bash
py -3.12 -m venv .venv                 # 本机默认 python 是 3.9,项目要求 >=3.10
.venv/Scripts/activate                 # POSIX: source .venv/bin/activate

# 依赖走 uv(本机 pip 通路病态,实测 uv 10s 完成、pip 超时)
uv pip install --python .venv/Scripts/python.exe -e ".[dev,async,ast,api,nuclei]"

# 可选:真浏览器确认(L6)、HTTPS 拦截、API 服务
uv pip install --python .venv/Scripts/python.exe -e ".[headless,mitm]"
python -m playwright install chromium
```

After installing, run the self-test first. It does not touch the network
(it starts a local range + runs every detection layer):

```bash
python -m xssentinel --self-test
```

**It is slow** (minutes; default cap 900s, tunable via `XSSentinel_SELFTEST_TIMEOUT`),
not a smoke test. If you only want to confirm the install worked,
`python -m xssentinel --help` printing its help is enough.

---

## 2. Three commands

```bash
# ① 扫一个 URL(最常用)
xssentinel -u "https://target.example/search?q=1"

# ② 让爬虫自己找端点和表单(含无参数的纯 DOM 页面)
xssentinel -u "https://target.example/" -c --crawl-depth 2

#    默认同源;要放开到某个前缀(比如同站的另一条路径)才用 --scope
xssentinel -u "https://target.example/app/" -c --scope "https://target.example/app/"

# ③ 要机器可读的结果 + 真浏览器确认
xssentinel -u "https://target.example/search?q=1" \
           -f sarif -o out.sarif --headless
```

`-f` supports `html / json / csv / sarif / junit / markdown / burp / nuclei`.
When unsure of the budget, use the presets instead of hand-tuning parameters:

```bash
xssentinel -u URL --scan-policy quick     # 冒烟:最少请求
xssentinel -u URL --scan-policy deep      # 深扫:预算拉满
```

Batch (one URL per line, `#` comments) and traffic imports:

```bash
xssentinel --batch urls.txt -o reports/
xssentinel --har capture.har            # 浏览器 DevTools / Burp 导出
xssentinel --openapi spec.json          # 声明面,含从未被访问的路由
xssentinel --raw-request captured.txt   # Burp "copy as raw"
```

---

## 3. Exit codes: the thing you should understand first in this project

| Code | Meaning | What you should do |
|---|---|---|
| **0** | Scan finished. **0 findings is still 0** | Use section 4 below to confirm this scan actually reached the target |
| **1** | Appears only when `--exit-code N` is passed and the hit count is ≥ N (off by default) | For CI gates; `--exit-code 1` means "red if any hole" |
| **2** | Usage error (argparse) | Read the error message |
| **3** | **Scan incomplete; this result must not be used to conclude "no vulnerabilities"** | Read the `[!] Why:` line |

**The distinction between 0 and 3 is deliberate.** Target unreachable, a proxy
swallowing the traffic, a failed TLS handshake —
all three report 0 findings; merging them with "scanned and clean" into one exit code
would disguise "not tested" as "tested and clean". That is why the not-tested cases
get their own code, 3.

The correct way to write this in CI:

```bash
xssentinel -u "$URL" -f sarif -o out.sarif --exit-code 1
case $? in
  0) echo "clean" ;;
  1) echo "vulnerable" ; exit 1 ;;
  3) echo "INCONCLUSIVE - do not merge on this" ; exit 1 ;;
esac
```

---

## 4. Four environment traps that make people misread results

**① Environment proxy.** `requests` respects `HTTP(S)_PROXY` by default. If the host
has a global proxy set, requests to intranet/loopback addresses get taken over by
the proxy, and what you get back is **the proxy's** answer.
The tool now prints a one-line notice at startup; to go direct, use
`NO_PROXY=127.0.0.1,localhost` or temporarily `unset HTTP_PROXY`.

**② `%TEMP%` not writable.** In some hardened environments (Low integrity label,
containers with read-only mounts) `tempfile.gettempdir()` silently falls back to the
current directory, and third-party libraries leave junk files in your working directory.
The CLI already probes writability at startup and redirects; when it relocates it prints
`[*] System temp dir not writable; using ...` — seeing that line means a redirect
happened, not an error.

**③ Running the full test suite in a single process hangs.** This is not a performance
issue: once some async/DOM test binds the event loop, every subsequent sync Playwright
call fails with "Sync API inside the asyncio loop". You must use the batched runner:

```bash
python tests/run_all_batched.py --quiet              # sequential, ~60-75 min here
python tests/run_all_batched.py --quiet --jobs 4     # parallel: 268 files in 616s, measured 2026-11-02
```

Both modes produce the same per-file verdicts; `--jobs` only changes wall-clock time.
Quote the **skip count together with the pass count** — a gate whose whole files were
skipped contributed nothing.

**④ Local loopback degradation.** Some security software intermittently cuts loopback
TCP, which shows up as random failures. Re-run the single file first; if the re-run
passes, record it as "unverified" — do not treat it as a regression.

---

## 5. After you have the results

```bash
xssentinel -u URL --poc-dir poc/     # 每个确认漏洞一份可执行 PoC + curl
xssentinel --diff before.json after.json   # 修复前后对比
xssentinel --verify-fix URL          # 复验某个修复
xssentinel --serve                   # REST API 微服务模式
xssentinel --mcp                     # MCP server,接进 AI 工作流
```

Whether to trust a finding comes down to two fields:

- `confidence` — `high` means semantic confirmation or browser-executed evidence exists;
  `low` is a lead, not a conclusion
  (e.g. `dom_sink_reachability`: the data reached the sink but no execution was observed).
- `context` — which context the reflection landed in. The same payload in `html_body`
  and in `script_string` leads to completely different conclusions.

---

## Where to look first when something goes wrong

| Symptom | Look at |
|---|---|
| 0 findings but you know the site has holes | Is the exit code 3? Is there a `[!] Why:`? Is a proxy in effect? |
| The report cannot be written | Output directory permissions; on POSIX reports are written 0600 |
| All browser-related layers are skipped | `python -m playwright install chromium`; `%TEMP%` writability |
| You want to add a detection capability | [`CONTRIBUTING.md`](../CONTRIBUTING.md); a new layer must register in both `coverage.LAYERS` and the `layer_coverage` matrix |
