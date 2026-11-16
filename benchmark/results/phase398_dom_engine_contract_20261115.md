# Phase 398 / `dom_engine` 契约声明点测量（修复前）

日期：2026-11-15。**测量轮，产品代码零改动**。证据：
`benchmark/results/phase398_contract_probe_20261115.json`，探针
`dev/_p398_contract_probe.py`（`dev/_` 前缀，按仓库约定不入库）。

## 结论先行

Phase 397 把 `off` 修成真正的「关闭 DOM 层」，但**CLI 仍不认这个值**：
`--dom-engine off` 被 argparse 以 `invalid choice` 拒绝（rc=2），而 MCP
input schema 的 enum 早就含 `off`。中英 README 也只按三个值描述。
同一份契约的声明点散在 4 处，彼此没有守卫钉在一起。

另量出一处**记账外的新问题**：REST `api/server.py` 对 `dom_engine`
没有任何值域校验，任意未知字符串（如 `bogus`）会被 202 接受并直通
`Scanner`，最终在两侧 `_resolve_dom_engine()` 里落到
`DynamicDomAnalyzer` 构造 —— **静默启动真 Chromium**，与 Phase 397
修掉的「`off` 被忽略」同形。**本轮不修 REST**（见「范围」）。

## 五个值 × 五个入口（真实入口，非替身推演）

| 值 | CLI `parse_args` | MCP enum | REST `_handle_create_scan` | core sync / async 解析器 |
|---|---|---|---|---|
| `auto` | 接受 | 含 | 202 直通 `auto` | sentinel / sentinel（构造浏览器） |
| `playwright` | 接受 | 含 | 202 直通 `playwright` | sentinel / sentinel |
| `static` | 接受 | 含 | 202 直通 `static` | none / none |
| **`off`** | **拒绝 rc=2** | **含** | 202 直通 `off` | none / none |
| `bogus` | 拒绝 | 不含 | **202 直通 `bogus`** | **sentinel / sentinel** |

- CLI 读的是 `xssentinel.__main__.build_parser("scan")` 里真实的
  `--dom-engine` action（`choices` / `default`），不是抄来的常量。
- MCP 读的是真实 `_TOOL_SCAN_SCHEMA["properties"]["dom_engine"]["enum"]`。
- REST 调的是真实 `_handle_create_scan`；替身 ctx 只回答 handler
  真正会发出的 `job_manager.create` / `start` 两个调用，`start` 故意
  不运行 worker（无扫描线程、无网络），且 `mark_completed` 一旦被
  调用就 ABORT —— 替身保真度按 Phase 201 续二的口径量过。
- core 用哨兵 analyzer 替换 `DynamicDomAnalyzer`，把「是否构造浏览器」
  与本机 Chromium 可用性解耦（沿用 Phase 397 守卫的手法）。

## 声明点清单（本轮集合相等判据覆盖前三行）

| 位置 | 形态 | 当前值域 |
|---|---|---|
| `xssentinel/__main__.py:523` | argparse `choices` | `auto/playwright/static` |
| `xssentinel/api/mcp_server.py:371` | JSON schema `enum` | `auto/playwright/static/off` |
| `README.md:429` | 文档花括号列表 | `{auto,playwright,static}` |
| `README.en.md` | 只讲默认 `auto`，未列值域 | — |
| `xssentinel/api/server.py:557` | **无声明**，body 直通 | 任意字符串 |

## 同一量具复测（修复后）

`dev/_p398_contract_probe.py` **量具未改**，只改产品代码；用
`P398_OUT=phase398_contract_probe_after_20261115.json` 另存，不覆写
带日期的修复前证据（`phase398_contract_probe_20261115.json`）：

- CLI `choices`：`auto/playwright/static` →
  **`auto/playwright/static/off`**；`off` 从 `SystemExit(2)` →
  `accepted=true`；`bogus` 仍拒绝；`default` 仍 `auto`。
- MCP enum、REST 五个 202 直通臂、core 十个解析结果**逐位不变**
  —— 本轮没有碰这些面，复测能看到这一点才说明量具没说谎。
- 真实 CLI 子进程（不是 parser 替身）：
  `python -m xssentinel --dom-engine off --version` **rc=0**；
  `--dom-engine bogus` **rc=2**；`--help` 输出
  `[--dom-engine {auto,playwright,static,off}]`。

## 范围（本轮做什么、不做什么）

- **做**：CLI `choices` 补 `off` + help 文案与 MCP 描述对齐；中英 README
  同步 `off` 的用法；新增守卫把 CLI / MCP / 中文 README 三处值域与
  core 解析器行为钉在一起（「两边都认」，不引入豁免名单）。
- **不做**：不改默认值（仍 `auto`）、不改判定层 / 语料 / 预算 /
  REST 契约、不给 REST 加值域校验。**REST 任意值直通列为独立一轮**，
  因为它改的是 API 接受域（收紧会拒绝今天被接受的请求），需要自己的
  兼容性与门禁轮，不与本轮 CLI 面混做。
- **版本口径**：只在 `choices` 里增加一个合法值，不改现有参数语义或
  默认值 ⇒ 按 CHANGELOG「版本策略」属新增能力，不是 `BREAKING:`。

## 验收（本轮自己的运行）

- 守卫 `tests/test_phase398_dom_engine_contract.py`
  **6 passed / 0 skipped**；变异 `dev/phase398_mutations.py`
  **4/4**（CLI choices / MCP enum / 中文 README / 英文 README 各删
  `off`，baseline 绿 → mutated 红 → restored 全守卫绿，字节级还原；
  文本模式读写后 blob 哈希与 HEAD 一致，CRLF 未被改写）。
- 同一量具复测见上节；真实 CLI 子进程 rc=0 / rc=2 / `--help`
  四值显示已单独确认。
- 四档 strict gate（quick/full × sync/async，全部 FP0/FN0，
  SKIP 见下）、range4 双引擎与 ruff 数字见 CHANGELOG Phase 398
  验收节（引用绿必须带 skip 数）。**未跑**：range3、邻接组、
  pytest 全量分批门 —— 本轮只改 CLI choices 与两份 README，
  不碰判定层/语料/预算/REST，397 全量门 319/319 仍成立；
  不虚报，也不拿旧证据顶本轮。

## 复现

```
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost PYTHONPATH=""
.venv/Scripts/python.exe dev/_p398_contract_probe.py
```
