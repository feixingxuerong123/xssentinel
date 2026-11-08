# `javascript:` Location 修复 + 官方 1013 例全量 scorecard（2026-11-08）

> 两件事，两轮证据。跑分在**未提交的 WIP 工作树**上完成（含用户 Phase 364
> 的形状语料改动），**不是已发布 1.4.3 的成绩**。

## 结论摘要

| | 结果 |
|---|---|
| 缺陷修复 | `partial` **14 → 0**、`requests_failed` **26 → 0**、`InvalidSchema` **26 → 0**，判定逐位不变 |
| 四档门禁 | quick 64 / full 194 × sync / async **全部 exit 0** |
| 官方全量 | **TP 975 / FN 38 / FP 0，P 100%、R 96.2%、F1 0.981**，1959.1s，controls 27 零误报 |

## 一、归因纠正（上一轮我判断错了）

上一轮报告写的是"扫描器把 `javascript:` 伪协议当 HTTP 目标发"。**不对**。
完整调用链是：

```
stateless poly_007 (payloads.json:15304) → verifier.mark(style="concat")
  → 探针经 params 发给靶场
  → XSSMaze 把它反射进 302 Location: javascript:...
  → requests 自动跟随；GuardedSession.resolve_redirects 无条件 yield from super()
  → 下一跳 PreparedRequest.url = "javascript:..." → get_adapter 抛 InvalidSchema
  → Requester._send 记 tally.note_failure → report.scan_status = partial
```

改调用点或载荷生成处都无效；**拦截点必须在 redirect hop**。
（async 侧 aiohttp 抛的是 `NonHttpUrlRedirectClientError`，类型不同、同源。）

## 二、修法：一个定义 + 正确的 hop 落点

- 新增 `xssentinel/core/url_safety.py::is_safe_redirect(base_url, location)`：
  **先 `urljoin` 再 `urlparse`**，白名单 `{"http","https"}` + `netloc` 非空。
- 实测（Python 3.12）：`JAVASCRIPT:` / `java\tscript:` / `java\nscript:` /
  `data:` / `vbscript:` / `file:` / `blob:` / `mailto:` 全部原样保留且 scheme 归一，
  白名单一次挡住；`/next`、`//cdn/x`、`?q=`、`#frag` 解析成合法 http(s)，不误杀。
  用白名单而非黑名单（项目自己在 `sandbox.py:657` 就记录了 `jav&#x09;ascript:` 变形）。
- 接线到 `GuardedSession.get_redirect_target(resp)`：requests 在循环前后**每一跳**
  都调它，返回 `None` 即 `while url:` 不进入 → 3xx 原样交回、**一个请求都不发**，
  所以 tally 不记失败，扫描状态保持 `completed`。

改动文件：`xssentinel/core/url_safety.py`（新）、`xssentinel/core/requester.py`、
`tests/test_redirect_scheme_gate.py`（新）。**没有改载荷、没有改判定语义。**

## 三、证据链

| 环节 | 结果 |
|---|---|
| 红测（修前） | **4 failed**（js/data/vbs/file 全 `InvalidSchema`）/ 3 passed（合法跳转） |
| 修后守卫 | **27 passed**：4 行为 + 3 反向对照 + 16 纯函数边界 + 4 AST 源码断言 |
| 变异对照 | baseline 27 → 把方法改回无条件跟随 ⇒ **红 5 例**（4 行为 + 1 源码断言）→ restored 27，sha256 逐字节一致 ⇒ PASS |
| 回归组 | **160 passed**（egress / failure_reasons / cache / phase357 / 362 / 364 / mixin / noqa / no_undefined / silent_except 等） |
| 四档门禁 | quick sync 64 `0 SKIP`、quick async 64 `1 SKIP`、full sync 194 `0 SKIP`、full async 194 `12 SKIP`，**FP0/FN0/ERROR0，全 exit 0** |
| XSSMaze 86 例前后对照 | `BEFORE`: 72 completed / 14 partial、failed 26、TP59/FP0/findings 96 → `AFTER`: **86 completed / 0 partial**、failed 0、**TP59/FP0/findings 96 逐位不变** |
| ruff | 全仓 `All checks passed` |

**这一条最关键**：修复只消掉了报表里的失败状态，判定一个数没变。

## 四、官方 1013 例全量 scorecard

### 口径

- 官方 runner `dev/_xssmaze/benchmark.py`，`--reach server`，
  `--custom-scanner "<venv py> dev/_xssmaze/wrapper.py {URL}"`，
  `--detect-json 'findings[].url'`，GT 来自官方 `/map/json` 的 `exploitable`。
- 目录 1064 endpoints / 175 类；计分 population **1013**（server reach），
  27 controls 单列 FP，24 client-reach 不计分。
- **与历史口径的一处差异**：`--scanner-timeout 90`（历史默认 30s），
  为本机 loopback 抖动放宽；只影响超时，不影响判定逻辑。
  1039 次 wrapper 调用 **0 个非 0 rc / 0 超时**。

### 结果

```
Scanner          TP    FN    FP  Precision   Recall     F1      Time
xssentinel      975    38     0    100.0%    96.2%   0.981   1959.1s
```

- 按 vuln class：`reflected-html 442/466`、`reflected-attr 252/258`、
  `dom 169/174`、`reflected-js 93/95`、`stored 9/10`、
  `csti 5/5`、`prototype-pollution 5/5`。
- 最差 category：`postmethod 0/6`、`post 0/2`、`jf 0/1`、
  `headless 1/6`、`multipart 1/4`、`headerinj 3/6`。
  POST / multipart / headless 类与"runner 只传 URL、wrapper 用 GET 扫描"有关，
  不全是扫描器能力缺失，但确实是当前覆盖缺口。
- 产物：`benchmark/results/xssmaze_full_20261108.{json,md}`，
  逐例日志 `TEMP/xmz_full_invlog_20261108.tsv`（1039 行）。

### 与历史基线的对比（不要误读）

| 版本/轮次 | TP | FN | FP | F1 |
|---|---|---|---|---|
| Phase 342（2026-10-30） | 944 | 69 | 0 | 0.965 |
| 1.4.3 / p363final（2026-11-06） | ≈969 | ≈44 | 0 | 0.9778 |
| **本轮 WIP 树** | **975** | **38** | **0** | **0.981** |

+6 TP / −6 FN **不能归因给本次修复**：86 例前后对照已证明修复零判定变化。
更可能的来源是①用户未提交的 Phase 364 形状语料，②更宽的超时减少了环境性
伪影（本轮 0 超时），③本机 loopback 状态更好。这是"WIP 树的当前成绩"，
不是 1.4.3 的复测成绩，也不是修复带来的提升。

## 五、未修的缺口（如实列出）

1. **async 对称缺口**：aiohttp 对同样的 Location 抛 `NonHttpUrlRedirectClientError`
   并计入失败。试过在 `on_request_redirect` trace 里删 `Location`，但 headers 是
   只读 `CIMultiDictProxy`（已实测）⇒ 不可行。要修需 `allow_redirects=False`
   + 自管重定向，属另一量级。本轮 batch 默认 sync，14–16 个 partial 全是 sync。
2. **同族位置**（`urljoin` 后直接请求、无 scheme 白名单）：
   `upload_probe.py:147/257`、`async_scanner_layers.py:930/1012`、
   `async_scanner_crawl.py:531`、`client_layers.py:339`、`verify_fix.py:230-243`；
   `async_scanner_common.py:507` 仍是黑名单且不挡 `data:`。
   共享 helper 已就绪，接线时别再手写第二份定义。
3. **WIP 既有红项，非本轮引入**：`test_architecture_scale`
   （`scanner.py 2793 > 2650`）、`test_doc_gate_parity`
   （CHANGELOG 1.4.3 vs `__version__` 1.4.4）。发版前需按项目规矩处理。

## 六、取舍

- 本轮修复已闭环，**不建议继续在 redirect 层加东西**；下一步最值钱的是把
  `is_safe_redirect` 接到上面第 2 点的同族调用点（一次接线 + 一次全量门）。
- 38 个 FN 里 `postmethod 0/6` + `post 0/2` 是结构性的：官方 runner 只喂 URL，
  POST 端点拿不到 body。要么给 wrapper 按 `/map/json` 的 `method`/`params` 补
  POST 参数，要么明确把它标为"不在本口径内"。这比再补 payload 更能改数字。
- 本轮未提交任何 commit，未触碰用户 Phase 364 WIP 的其他部分。
