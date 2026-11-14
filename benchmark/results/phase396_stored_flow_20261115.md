# Phase 396 / NodeGoat 存储流：零请求静默退出的根因与修复

日期：2026-11-15。真实靶：OWASP NodeGoat 官方 master + 官方种子，`127.0.0.1:20506`（mongod 27018）。
事实表，**不与 XSSMaze / 194 矩阵 / bWAPP / Juice Shop 的任何数字并列**（Phase 380 规则）。
证据：`phase396_stored_trace_20261115_{baseline,fix,budget,after}.json`。

## 结论先行

Phase 395 记账的 (c)「auto fetch 零请求静默退出」根因**不是** `_send` 内部的失败，
而是 **`scan_stored_auto` 的页面抓取读了被污染的 GET LRU**：`_send` 从未被调用。
把这一处改成 `cache_get=False` 后，同一场扫描从 3 findings 变成 4 findings，
多出的层是 **`stored`** —— 认证页存储型 XSS 端到端打通。

## 四臂事实表（真实 CLI 入口，同一份 `-b connect.sid` 会话）

| 臂 | 页面字节 | 页面身份 | faces | `scan_stored` | findings | 层 |
|---|---|---|---|---|---|---|
| baseline（修前） | 7208 | 登录页 `name="userName"`（**缓存命中**） | 0 | 0 | 3 | dom / svg_xss_svg_script / trusted_types_no_policy |
| fix（探针模拟 `cache_get=False`，产品未改） | 8598 | 认证 profile 页 | 1 | 1 | **4** | 上述 + **`stored`** |
| budget（`--max-requests 12`） | 8630 | 认证 profile 页 | 1 | 2 | 3 | 无 stored（47 次 `BudgetExhausted`，写不进去） |
| **after（真实产品改动后复测）** | 8630 | 认证 profile 页 | **1** | **1** | **4** | 上述 + **`stored`** |

`baseline` 臂：`get_calls=39 / send_calls=36 / get_cache_hits=4`，stored pass
**确实被调用**（`pages_enter=1, auto_enter=1`），页面抓取那次 `from_cache=true`、
`hit_delta=1`、`_send` 无对应记录。`after` 臂同一量具：`get_cache_hits` 4→3、
`send_calls` 36→41、`scan_stored_calls=1`。

## 根因链（每一步都有打点）

1. 主扫描中某发 `/profile` 的 bare-URL GET 返回 **7208 字节登录页**（L8_cookie
   canary 用 `Cookie:` 头覆盖会话是一次合法弹回，Phase 395 记账 (b) 的设计行为）。
2. `Requester.get()` 的缓存 key **只有 URL**（`cache_get=True`、无 params、无
   per-request headers），status 200 → 该登录页被写进 LRU。缓存看不到 session jar
   的状态，这一点 `Requester.get()` 的 docstring 与 Phase 176c 已明确警告。
3. `scan_stored_auto()` 的页面抓取用默认 `cache_get=True` → **命中脏缓存** →
   `discover_write_faces` 只看到登录表单，被 `_AUTO_SKIP_FORM` 过滤 → `faces=0`
   → `ran=0`，整段静默退出且 `_send` 从未被调用（即「零请求」）。
4. 同一场扫描里 `scan_stored` 的 view GET 都显式 `cache_get=False`，拿到的是
   8598 字节**正确认证页** —— 会话根本没死，只是缓存给了错误页面。

**勘误**：Phase 395 记账推测「`_send` 内部在响应后到返回之间的某处失败，待查」。
本轮打点证明 `_send` 根本没进；该推测是「打点看不到 `_send`」造成的误判，
以本表为准。带日期的 CHANGELOG / OPTIMIZATION 原文保留不改。

## (a) 预算耗尽跳过 stored-auto：本轮在 CLI 入口未复现

`--max-requests 12` 臂里 `pages_enter=1 / auto_enter=1 / scan_stored_calls=2`，
stored pass **没有被跳过**；`scanner.py:517` 的 `not stopped` 只在异常冒泡到
`scan_target` 并置 `stopped=True` 时生效，而这次 47 次 `BudgetExhausted` 都被
各层内部消化了。附带观察（记账，不修）：`Budget.spend` 先 `total += 1` 再抛，
`total` 一路涨到 59 而 `max_total=12`。**本轮不改预算语义、不动 `not stopped`**。

## 修法与边界

- 唯一产品改动：`xssentinel/core/scanner_stored_auto.py` 的页面 GET 改为
  `self.req.get(page_url, cache_get=False)`，与 `scanner_stored.py` 里所有 view
  GET 的既有契约一致（这是「同一契约手写两遍」家族里漏掉的那一份）。
- 不改判定层、不改语料、不改 CLI / MCP / REST 契约、不改 (b) 的 canary 行为、
  不改预算。代价：每个 auto 页面多发 1 个 GET（`max_pages` 上限 3）。
- 守卫 `tests/test_phase396_stored_auto_fresh_fetch.py` **4 例**：脏缓存下仍发现
  真实 write face（且含「同一 Requester 在认证态下默认 GET 仍返回登录页」的对照，
  证明守卫不空转）、干净缓存路径不回归、显式 `page_text` 不发请求、调用点源码契约。
  真实 `Requester` + 真实 loopback server + 真实 `CoverageTracker`；只 stub
  `scan_stored`（否则会打完整载荷阶梯），stub 仅记录 kwargs 并返回 False。
- 变异 `dev/phase396_mutations.py`：**1/1**（去掉 `cache_get=False` → 守卫红，
  baseline 绿 / mutated 红 / restored 绿，字节级还原）。
- 邻接回归：stored + requester + cookie canary **59 passed / 3 skipped**。

## 复现

```
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
.venv/Scripts/python.exe dev/_p396_stored_trace.py http://127.0.0.1:20506 after
.venv/Scripts/python.exe -m pytest -q tests/test_phase396_stored_auto_fresh_fetch.py
.venv/Scripts/python.exe dev/phase396_mutations.py
```

探针 `dev/_p396_stored_trace.py` 打的是**真实 CLI 入口**
（`xssentinel.__main__.main`，与 Phase 392 runner 完全相同的参数），
不是照着产品重写一份副本。`fix` 臂通过请求期 flag 强制 `cache_get=False`
来模拟改动，用于「只动一个变量」的因果对照；`after` 臂是产品代码本身。

## 未做 / 诚实边界

- 靶场状态：本轮多次覆写 `profile`（`firstName` 等）并触发 stored 写入，
  与 Phase 392 已披露的写入同族；本表是事实表，**不算 F1、不算率**。
- NodeGoat 只有 7 个投递形状，不构成外部效度结论；商业工具仍零对跑，
  XSSMaze 仍是唯一 F1 来源。
- `stopped=True` 的那条路径（MCP/API 层 wall-clock cancel）本轮**没有复现**，
  保持为观察项，不宣称已修。
- **缓存污染本身没修**：L8_cookie canary 弹回的登录页仍会被写进 LRU，
  本轮只修 stored 路径的读取契约。其它 bare-URL 读取者（例如主扫描的
  前置页面 GET）理论上仍可能拿到陈旧页面；194 矩阵与全量分批门全绿，
  但没有针对这一面的独立测量，列为观察项而非已解决。
- 终树门禁数字见 CHANGELOG Phase 396 验收节。
