# Phase 400 / GET LRU 缓存写条件不对称：污染源头定谳与修复

日期：2026-11-17。事实表，**不与 XSSMaze / 194 矩阵 / bWAPP / NodeGoat 任何数字并列**（Phase 380 规则）。
证据：`benchmark/results/phase400_*_20261117.json`；守卫 `tests/test_phase400_cache_write_headers.py`；变异 `dev/phase400_mutations.py`。

## 结论先行

承接 Phase 396 留下的观察项「缓存污染本身没修，其它裸 URL 读取者理论上仍可能拿陈旧页」。
本轮把它定谳为一个**具体代码缺陷**，不是理论风险：

`Requester.get()` 的 GET 缓存**读**条件含 `not headers`（requester.py:609），**写**条件**漏了** `not headers`（原 requester.py:628-629）。
于是带 `headers=` 的请求（L8_cookie / L8_header canary、error/redirect 探针）虽然按契约跳过读缓存，
却把响应**写进**了裸 URL 的 LRU。当 canary 被应用弹回登录页时，那张登录页就成了该 URL 的缓存条目；
之后所有默认 `cache_get=True` 的裸 GET（advanced_layers、crawler、scanner_layers、second_order 等）
静默读到登录页——**即使操作员会话完好**（Phase 394 的 pin 恢复把 cookie 状态维持得很正确）。

Phase 396 修的是**一个读者**（`scan_stored_auto` → `cache_get=False`）；本轮修的是**污染源**：
header-varying 的请求不许写缓存，与"不许读缓存"对称。一处改动保护所有读者。

## 先量后修（三步，每步有证据）

### 1. 静态盘点

产品代码里 `req.get()/requester.get()` 调用点 14 处（不含 dict.get / 测试）：
- 已显式 `cache_get=False`（4）：`scanner_stored.py` ×4、`scanner_stored_auto.py:51`、`verify_fix.py` ×2
- 裸 GET 用默认 `cache_get=True`（10）：`advanced_layers.py:65/83`、`content_layers.py:301`、
  `scanner_crawl.py:56/152/165/287/415`、`scanner_layers.py:113/424`、`scanner.py:670`、
  `second_order.py:143`、`client_layers.py:95/137/350`、`transport_layers.py:187/208/399`、
  `cli_commands.py:627`、`cli_runner.py:303`、`sqli.py:127`（后者带 params，天然跳过缓存）

带 params / 带 headers 的调用天然跳过缓存读写；**裸 URL 调用暴露在脏页面前**。

### 2. 机制量具（`dev/_p400_cache_poison_impact.py`）

自包含 loopback 靶场（good cookie → AUTH 页；其它 → LOGIN 页），真实 `Requester`。
先以匿名裸 GET 把 LOGIN 写进 LRU，再恢复 good cookie，逐调用形状测返回：

| 调用形状 | 结果 | from_cache |
|---|---|---|
| 裸 GET（advanced/crawler/layers/stored 读法） | **LOGIN(stale)** | true |
| params GET（sqli baseline） | AUTH(fresh) | false |
| headers GET（canary） | AUTH(fresh) | false |
| `cache_get=False`（Phase 396 修法） | AUTH(fresh) | false |
| 对照：干净会话裸 GET | AUTH(fresh) | false |

结论：脏页进 LRU 后，只有**裸 GET 读者**中招。

### 3. 污染源是否存活（`dev/_p400_poison_source_live.py`）

真实 `Requester` 带 pinned cookie，忠实复刻 L8_cookie 序列：
1. `get(url, headers={"Cookie": "connect.sid=evil"})` → LOGIN（canary 弹回）
2. 检查 jar：只剩 `connect.sid=good`（Phase 394 pin 恢复生效，会话是好的）
3. `get(url)` 裸 GET → **LOGIN，且 `from_cache=true`**

**关键定性**：会话状态是对的、canary 也按契约跳过了读缓存，但裸 GET 仍吃到登录页。
dump 缓存证实：**canary 那次调用就把 LOGIN 写进了 LRU**——`after canary: cache keys=['.../profile']`。

### 4. 变异对照（根因坐实）

用 monkeypatch 复刻"写条件补 `not headers`"的假想修复，同一量具：

| 变体 | canary 写缓存？ | 后续裸 GET |
|---|---|---|
| baseline（产品现状） | True | **LOGIN** |
| fixed（写条件补 not headers） | False | **AUTH** |

写/读条件不对称是根因，非环境、非时序噪声。

## 修法与边界

- **唯一产品改动**：`xssentinel/core/requester.py` 缓存写入条件补 `and not headers`，与读条件对称。
- 不改判定层、不改语料、不改 CLI/MCP/REST 契约、不改 pin 恢复、不改 canary 行为、
  不改 Phase 396 的 stored_auto 修复（保留，属纵深防御）。
- 代价：带 headers 的 GET 不再填充 LRU，后续同 URL 的裸 GET 会多发 1 次真实请求。
  这类调用是少数（canary / error 探针），且缓存本就不该被它们污染。

## 影响面：仅 sync 路径

GET LRU 是 sync `Requester` 特有的（`xssentinel/core/requester.py` 的 `_cache`）；
async 引擎用 aiohttp session，无此缓存实现（全仓 grep `_cache|cache_get|cache_hits`
于 `async_scanner*.py` 零命中）。所以：
- **本 bug 只存在于 sync 路径**，async 天然不受影响。
- async strict gate 通过是**回归确认**，不是修复验证（它没有这段缓存）。
- 修在 sync `Requester` 一处即可，无需 async 对偶改动（不存在对偶实现）。

## 验收

- 守卫 `tests/test_phase400_cache_write_headers.py` **4 例**：
  header 请求不写缓存 / 端到端不被污染 / 裸 GET 仍写缓存（防守卫空转的回归钉）/
  读条件未变（回归钉）。修前 **2 failed / 2 passed**（正是两条污染测试红），修后 **4 passed**。
- 变异 `dev/phase400_mutations.py`：baseline 绿 → 删 `not headers` 红 → 字节还原绿（PASS）。
- 邻接回归：requester / cookie stickiness / stored_auto **10 passed**。
- ruff：全仓零基线。
- quick strict gate sync（20510）：**64 scored / 0 SKIP**，FP0/FN0/ERROR0，
  性能 155.3s vs ceiling 330s（baseline 163.7s @2026-11-13，margin 2.0x）。
- quick strict gate async（20511）：**63 scored / 1 SKIP**，FP0/FN0/ERROR0，
  性能 158.0s vs ceiling 350s（baseline 173.2s @2026-11-13，margin 2.0x）。
  如上，async 无此缓存，此行仅作全引擎回归。
- 全量 192 sync（20512）：**194 scored / 0 SKIP**，FP0/FN0/ERROR0，
  性能 416.3s vs ceiling 795s（baseline 397.1s @2026-11-13，margin 2.0x）。
  这是最强回归证据：改动虽不碰判定层，但改了页面获取来源，故按纪律跑全量确认。
