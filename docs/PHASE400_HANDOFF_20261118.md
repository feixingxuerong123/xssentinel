# Phase 400 交接文档：headless 认证重放修复

> 面向下一个接手者（人或 AI）。本文件自包含，不依赖对话上下文。
> 写于 2026-11-18 23:4x（GMT+8）。**凡标注「未完成」的项，不要当成已完成。**
>
> **接手续记（2026-11-18 23:5x，GMT+8）**：§0 / §3.6 / §4 / §6 已按实跑结果回填——
> sync + async 两门均全绿、变异对照 4/4 RED。补记处标 `[接手补记]`。

## 0. 状态速览

| 项 | 状态 | 证据 |
|---|---|---|
| P0：headless 重放不注入会话 Cookie | **已修** | §3.1–3.4 |
| P0 附带：POST 重放发成 JSON 而非 form | **已修** | §3.5 |
| 新守卫（9 例） | 全绿 | `pytest tests/test_phase400_headless_auth_cookies.py` → 9 passed |
| 相邻测试（8 文件） | 全绿 | 80 passed |
| ruff（改动文件） | 全绿 | `All checks passed!` |
| DVWA 真靶复验 | 通过 | `evidence_class=browser-executed`，弹窗 token 命中 |
| sync 全量 194 门 | **全绿** | `113/0/81/0`，0 SKIP，433.4s，§4 |
| async 全量 194 门 | **全绿** | `107/0/75/0`，12 SKIP，510.9s，§4 |
| 变异对照 | **4/4 全 RED，VERDICT=PASS** | §3.6；sha256 字节还原一致 |
| P1：默认模式不自证执行 | **未修**（产品决策项） | §6 |

当前工作区**不是干净树**：`benchmark/server.py` 曾缺失（已 `git checkout --` 恢复），
新增文件均为本轮产物，详见 §8。

## 1. 问题与根因（先量再修）

DVWA（真靶，`C:/pentest-targets/DVWA`）high 档反射面，同一载荷：

| 条件 | 结果 |
|---|---|
| 独立 Playwright，注入 `security=high` + `PHPSESSID` | dialog `['xssv_58f47aff']` |
| 独立 Playwright，不注入 cookie | 302 到 `login.php`，无 dialog |
| `xssentinel --headless` | `evidence_class=browser-refuted`，`detail="no dialog"` |

根因链：

1. `verifier.verify_headless()`（`xssentinel/core/verifier.py`）**没有 cookies 参数**；
2. 调用方只传 `headers=dict(session.headers)`；
3. requests 的 Cookie 在 `session.cookies`，**不在** `session.headers`；
4. Playwright `browser.new_page()` 拿到的是无会话上下文 → 登录墙 → `no dialog`；
5. 附带：`set_extra_http_headers({"Cookie": ...})` 会被 Playwright 拒绝，原代码
   `try/except` 吞掉异常，导致**同一 header 字典里的 Authorization 也一起丢失**。

这是「同一契约手写两遍」家族：HTTP 侧有认证，浏览器重放侧没有。

## 2. 改动清单（逐文件）

### 2.1 产品代码

- `xssentinel/core/verifier.py`
  - 新增 `session_cookies(session) -> dict`：requests jar → dict，**唯一收口**，
    禁止各调用点手写 jar 转换。
  - 新增 `_browser_cookie_entries(cookies, headers, url)`：合并显式 cookies 与
    `Cookie` header（后者按 `;` 拆分），按 name 去重，输出 Playwright 结构。
  - `verify_headless(..., timeout=20, cookies=None)`：
    - `page.context.add_cookies(...)` 注入会话；
    - `Cookie` 从 headers 剔除后再 `set_extra_http_headers`（Authorization 得以保留）；
    - POST 重放 `data=` 改 `form=`（Playwright 默认把 `data` 发成 JSON，
      与 HTTP 探针的 form 载体不一致）。
- `xssentinel/core/scanner.py`：3 处调用点传
  `cookies=verifier.session_cookies(...)`（约 1474 / 2327 / 2451 行）。
- `xssentinel/core/async_scanner_verify.py`：新增 `_verify_cookies()`
  （合并 `self.cookies` 与 `auth_cookies`），调用点传入。
- `xssentinel/api/mcp_server.py`：`xssentinel_verify` 工具传
  `cookies=dict(args.get("cookies") or {})`；`xssentinel_propose` 把
  `cookies=args.get("cookies") or {}` 交给 `propose_and_verify`。
- `xssentinel/core/llm_propose.py`：`propose_and_verify(..., cookies=None)`，
  透传给 `verify_headless`。

### 2.2 测试与证据工具

- `tests/test_phase400_headless_auth_cookies.py`（新增，9 例）
  - 5 个行为例：真实 Chromium + 本地 auth-gated server（无 cookie 302 到
    `/login`，有 cookie 才渲染 payload）：显式 cookies / 无 cookies /
    `Cookie` header 兜底 / Authorization 存活 / POST 带 cookie。
  - 3 个源码断言：`scanner.py`(3)、`async_scanner_verify.py`(1)、
    `mcp_server.py`(1) 的每个 `verify_headless(` 调用块都必须含 `cookies=`。
  - 1 个函数形状断言：签名含 `cookies=`，函数体含 `add_cookies(`。
- `tests/test_async_headless_verify.py`、`tests/test_phase217_sync_headless_verify.py`：
  替身签名补 `cookies=None` 并记录，**不是放宽断言**。
- `dev/phase400_headless_cookie_mutations.py`（新增）：4 条变异（上下文注入、
  form 载体、async 调用点、sync 调用点），字节级还原 + sha256 校验。

## 3. 验证证据（按执行顺序）

### 3.1 修复前：守卫红

`pytest tests/test_phase400_headless_auth_cookies.py` → **7 failed, 2 passed**，
含 `TypeError: unexpected keyword argument 'cookies'` 与 3 个调用点断言红。

### 3.2 修复后：守卫绿

`9 passed in 8.07s`。

### 3.3 相邻测试

`pytest -q tests/test_async_headless_verify.py tests/test_phase217_sync_headless_verify.py
tests/test_phase193.py tests/test_fixes.py tests/test_llm_propose.py
tests/test_phase365_mcp_url_parity.py tests/test_phase366_propose_timeout.py
tests/test_phase400_headless_auth_cookies.py` → **80 passed**。

### 3.4 ruff

改动 9 个文件 → `All checks passed!`。

### 3.5 DVWA 真靶复验

命令形状：

```bash
python -m xssentinel -u "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=xssprobe" \
  -b "security=high; PHPSESSID=<sid>" -f json \
  -o benchmark/results/dvwa_scan_high_reflected_headless_after400_20261118.json \
  --progress none --log-level error --max-payloads 14 --max-transforms 12 \
  --threads 2 --timeout 10 --headless
```

结果（修复后）：

```json
"type": "reflected", "severity": "high", "confidence": "high",
"evidence_class": "browser-executed",
"headless": {"available": true, "confirmed": true, "outcome": "fired",
             "detail": "dialogs fired carrying the probe token: ['xssv_3f35af1a']"}
```

对照修复前：`evidence_class=browser-refuted`、`outcome=not-fired`、
`detail="no dialog"`。

### 3.6 变异对照（**4/4 全 RED，PASS**）`[接手补记]`

两个门跑完后重跑 `dev/phase400_headless_cookie_mutations.py`（接手时 4 个锚点
的字节 count 已分别是 1/1/1/2，与脚本 `expected` 一致，旧版 count=0 的问题不再复现）：

```
baseline: GREEN
context cookie install       RED (good)
form carrier                 RED (good)
async call site              RED (good)
sync call site               RED (good)
restored: GREEN
VERDICT: PASS
```

- 4 条变异逐条把修复点改坏，守卫每次都转 RED：`add_cookies`→`pass`、
  `form=`→`data=`、`cookies=self._verify_cookies()`→`_mutated_cookies()`、
  两个 sync 调用点的 `cookies=verifier.session_cookies(...)`→`_mutated_cookies(...)`。
- 全部语法合法（改的是值/关键字，不是制造语法错误），因此是守卫真实失败，
  不是 collection error 的假红。
- 字节级还原：改前/改后 sha256 逐文件比对一致
  （verifier `8bff6c6a98af455f` / scanner `3bfea33b44695189` /
  async_scanner_verify `953a12ba3f561313`），`xssentinel/` 下无 `MUTANT` /
  `_mutated_cookies` 残留，`git diff --stat` 与交接时一致。
- 还原后守卫复跑 `9 passed in 6.91s`。
- 首轮遗留记录（存档）：曾输出 `ABORT: async call site pattern count=0`，
  后 2 条未完成；该状态已被上面的完整重跑取代。

## 4. 门禁状态（如实）

全量矩阵 = `--strict-gate`（**不带** `--quick`），sync 与 async 各一次。
本轮 manifest 实际 **194 例**（不是记忆中的 192；以 runner 打印为准）。

启动过程中遇到两个环境问题，均已定位：

1. `.venv` 解释器：`import benchmark.runner` 报
   `OSError: [Errno 9] Bad file descriptor`（环境问题，非代码）。
2. `C:/Python39` 解释器：`ModuleNotFoundError: No module named 'server'`——
   真因是 **`benchmark/server.py` 被删**（`git status` 显示 ` D`）。
   已用 `git checkout -- benchmark/server.py` 恢复；该文件是 tracked 文件，
   不是本轮改动产生的删除。

两个门均已跑完（接手补记，2026-11-18 23:57 前）。sync 用端口 18931、async
用端口 18932，串行执行（async 在 sync 结束后才起），命令形状：

```bash
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
export TEMP=C:/Users/Administrator/.cache/xssentinel/tmp
export TMP=C:/Users/Administrator/.cache/xssentinel/tmp
C:/Python39/python.exe dev/gate_run_scratch.py --strict-gate --engine <sync|async> \
  --port <18931|18932> --concurrency 1
```

判读标准：`FP=0 / FN=0 / ERROR=0`，并记录 `env_gated_tests`（skip 数）。
两门实际数字已填入下方表格（接手补记；原文此处写「接手第一件事」的待办已消项）。

| 引擎 | 例数 | TP/FP/TN/FN | ERROR | SKIP | 判定 | 耗时 |
|---|---|---|---|---|---|---|
| sync | 194 | 113 / **0** / 81 / **0** | 0 | 0 | **PASSED** | 433.4s（上限 795s） |
| async | 194（182 计分） | 107 / **0** / 75 / **0** | 0 | **12** | **PASSED** | 510.9s（上限 840s） |

sync 原始判词（2026-11-18 23:49）：

```
TP/FP/TN/FN: 113/0/81/0
Recall: 100.00%   Precision: 100.00%   FPR: 0.00%   F1: 1.0000
[+] Performance budget PASSED: 433.4s vs ceiling 795s
[+] Strict quality gate PASSED: FP0 FN0 ERROR0 over 194 scored cases (0 SKIP)
```

async 原始判词（2026-11-18 23:57）：

```
TP/FP/TN/FN: 107/0/75/0
Recall: 100.00%   Precision: 100.00%   FPR: 0.00%   F1: 1.0000
[+] Performance budget PASSED: 510.9s vs ceiling 840s
[+] Strict quality gate PASSED: FP0 FN0 ERROR0 over 182 scored cases (12 SKIP)
```

12 个 SKIP 全部在 `html_element` 上下文（sync-only 用例的 async 臂），
按项目口径必须与 pass 数一起引用；不是回归。

原始报告在 scratch（工作区外）：
`C:\Users\Administrator\.cache\xssentinel\tmp\xssentinel_gate\benchmark_20261118_234913.json`（sync）
`C:\Users\Administrator\.cache\xssentinel\tmp\xssentinel_gate\benchmark_20261118_235753.json`（async）

## 5. 靶场环境（复现用）

- 源码：`C:/pentest-targets/DVWA`，git `d45ba3c4`（2026-05-30）。
- Web：`http://127.0.0.1:8080`，phpStudy Apache 2.4.39 + PHP 7.3.4（FastCGI）。
- DB：phpStudy MySQL 5.7.26，库 `dvwa`，`root/root`，端口 3306。
- 站点配置：`D:/phpstudy_pro/Extensions/Apache2.4.39/conf/vhosts/dvwa_8080.conf`
  （本轮新增；`Listen 8080`，DocumentRoot 指向源码）。
- 登录：`admin/password`，**必须带 CSRF**：先 GET `/login.php` 取
  `name='user_token' value='...'`，再 POST。
- 安全等级：靠 cookie `security=low|medium|high`（`dvwaSecurityLevelGet()`
  优先读 cookie），已用 `/security.php` 的
  `Security level is currently: <em>…</em>` 逐档验证。
- **会话易失效**：连续扫描后 PHPSESSID 会失效（表现为 302 到 login.php）。
  复跑前重新登录，命令见 §7.2。
- 当前会话 cookie：`benchmark/results/dvwa_live_cookie_20261118.txt`
  （仅本机靶场，勿外传）。

## 6. 未完成项（按建议顺序）

1. ~~补全量门~~ **已完成**（§4）：sync `113/0/81/0`（0 SKIP）、
   async `107/0/75/0`（12 SKIP），均 `PASSED`、FP0/FN0/ERROR0。
2. ~~补变异 3/4~~ **已完成**（§3.6）：4/4 全 RED、`VERDICT: PASS`，
   字节 sha256 还原一致、守卫复跑 9 passed。无需再改脚本锚点。
3. **P1 决策**：默认模式 finding 的 `evidence_class` 仍是
   `browser-unavailable`（"execution unverified"）。是否默认开启浏览器自证、
   还是把 `--headless` 作为显式契约，需要产品决策；本轮**未改**默认行为。
4. **P2 报告噪音**：死面（high `mtxMessage`）报告里会出现
   `trusted_types_no_policy`(medium)，按 contract 不算 XSS finding，但容易被误读。
5. **`impossible` 档对照**：DVWA 设计上应不可利用，可作负对照。
6. **未测**：DVWA DOM 型 XSS 模块、header/cookie 面、medium 的
   `<ScRiPt>` 大小写绕过（源码 `str_replace` 区分大小写，预期可绕，未实测）。

## 7. 复现命令

### 7.1 起服务

```bash
# MySQL（若未运行）
D:/phpstudy_pro/Extensions/MySQL5.7.26/bin/mysqld.exe \
  --defaults-file=D:/phpstudy_pro/Extensions/MySQL5.7.26/my.ini --console

# Apache
D:/phpstudy_pro/Extensions/Apache2.4.39/bin/httpd.exe \
  -f D:/phpstudy_pro/Extensions/Apache2.4.39/conf/httpd.conf -DFOREGROUND
```

两条都用后台任务方式启动（不要 `nohup` / `&`）。

### 7.2 重新登录并刷新 cookie

```python
import re, requests
s = requests.Session(); s.trust_env = False
b = "http://127.0.0.1:8080"
t = re.search(r"name='user_token' value='([0-9a-f]+)'",
              s.get(b + "/login.php", timeout=10).text).group(1)
r = s.post(b + "/login.php", data={"username": "admin", "password": "password",
                                   "Login": "Login", "user_token": t},
           allow_redirects=True, timeout=10)
assert "Logout" in r.text
print(s.cookies.get("PHPSESSID"))
```

### 7.3 真值 / 回验 / 扫描

```bash
python benchmark/realworld/dvwa_live_probe.py --out benchmark/results
python benchmark/realworld/dvwa_finding_replay.py \
  --cookie-file benchmark/results/dvwa_live_cookie_20261118.txt
python -m xssentinel -u "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=xssprobe" \
  -b "security=high; PHPSESSID=<sid>" -f json -o /tmp/out.json \
  --headless --max-payloads 14 --max-transforms 12 --threads 2 --timeout 10 \
  --progress none --log-level error
```

### 7.4 守卫与变异

```bash
python -m pytest -q tests/test_phase400_headless_auth_cookies.py
python dev/phase400_headless_cookie_mutations.py
```

## 8. 文件地图（本轮产物）

| 文件 | 说明 |
|---|---|
| `xssentinel/core/verifier.py` | 修复主体：cookies 注入 + Cookie header 拆分 + form 重放 |
| `xssentinel/core/scanner.py` | sync 3 个调用点 |
| `xssentinel/core/async_scanner_verify.py` | async `_verify_cookies()` + 调用点 |
| `xssentinel/api/mcp_server.py` | MCP verify / propose 传 cookies |
| `xssentinel/core/llm_propose.py` | `cookies` 参数透传 |
| `tests/test_phase400_headless_auth_cookies.py` | 9 例守卫（新增） |
| `tests/test_async_headless_verify.py` | 替身签名补 cookies |
| `tests/test_phase217_sync_headless_verify.py` | 替身签名补 cookies |
| `dev/phase400_headless_cookie_mutations.py` | 变异脚本（新增；4 条全 RED / PASS，sha256 还原一致） |
| `benchmark/results/dvwa_scan_high_reflected_headless_after400_20261118.json` | 真靶修复后证据 |
| `benchmark/results/dvwa_scan_high_reflected_headless_20261118.json` | 修复前 `browser-refuted` 证据（保留，不覆写） |
| `benchmark/results/dvwa_all_levels_20261118.md` | 三档实测报告（上一轮） |
| `benchmark/realworld/dvwa_live_probe.py` | 三档真值探针 |
| `benchmark/realworld/dvwa_finding_replay.py` | 扫描器 finding 载荷回验 |

## 9. 坑（必读）

1. **TEMP/TMP 分开写**：`export TEMP=TMP=C:/...` 会把 TEMP 写成字面
   `TMP=C:/...`，Playwright 报 `mkdtemp` 失败。必须
   `export TEMP=... TMP=...`。
2. **NO_PROXY 必设**：`127.0.0.1,localhost`，否则本地请求可能走代理，
   表现为"第一条正常、后续返回首页 HTML"。
3. **端口**：门禁用 189xx（避开 Windows 保留段 8810–9109）。
4. **safe-delete 上限**：全量门必须用 `dev/gate_run_scratch.py`（报告暂存在
   工作区外），否则跑到 ~50 例被杀且**不打印判词**。
5. **`benchmark/server.py` 缺失会伪装成** `ModuleNotFoundError: No module
   named 'server'`；先 `git status --short benchmark/server.py`，不要误判为
   sys.path 问题。
6. **DVWA 登录有 CSRF**：不取 `user_token` 直接 POST 会得到
   `CSRF token is incorrect`。
7. **DVWA 会话会被扫描打掉**：复跑前重新登录。
8. 本机 `wsl.exe` / `sc.exe` 被安全策略拉黑；Docker daemon 未运行 ⇒
   不要尝试容器版靶场，用 phpStudy 方案。
9. 不要为了让测试过而放宽断言：新增的 `cookies=` 源码断言是防「调用点回退
   到手写」的锁，删掉它等于没修。
