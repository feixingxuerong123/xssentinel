# Phase 397 / `dom_engine="off"` 契约修复与 parity 分歧定谳

日期：2026-11-15。事实表与归因，非跑分。证据：
本轮 `benchmark/results/phase397_bisect_20261115.json` 与
`phase390_parity_probe_20261114.json`；两臂 `shipped_fix` / `old_fetch` 对照
沿用 **Phase 396** 带日期的产物 `phase396_sri_control_20261115.json`
（不冒充本轮产物；本轮未生成 `phase397_sri_control_*`）。

## 结论先行

`pos-sri-01` 的双引擎分歧**不是 390–396 任何一轮产品代码引入**，也不是
「环境/时基玄学」。根因是一个明确的契约违反：**`dom_engine="off"` 在 sync 与
async 两侧的 `_resolve_dom_engine()` 都没有实现**，只要 Playwright 可导入，
operator 说「不要浏览器」时引擎照样构造 `DynamicDomAnalyzer` 跑真实 Chromium。

> **勘误**：Phase 396 的 CHANGELOG / AGENTS / OPTIMIZATION §8.27 把该分歧
> 记成「390–395 期间某轮使其复现，列 Phase 397」。8 臂对照推翻了这句：
> 把 2.1.0 以来改动的 4 个产品文件**全部**还原仍分歧且逐位一致。
> 带日期原文保留不改，以本表与 Phase 397 的勘误条目为准。

## 8 臂对照（同一量具、同一靶场、同一单 case）

`benchmark/server.py`、`benchmark/manifest.json`、`benchmark/adapters.py`、
`tests/conftest.py` 从 2.1.0 (`44403a3`) 到 HEAD **逐字节未变**；2.1.0 以来
只改了 4 个产品文件。每臂在一个工作区外的影子包里替换指定文件，**新子进程**
跑同一个 `pos-sri-01`，避免进程内 import 缓存说谎。

**归属说明**：本表在 **修复落盘之前** 构造，`current` 臂是当时尚未实现
`off` 的产品代码；`off_fixed` 只是在影子包里先试同一补丁。补丁随后才
落到真实产品文件（`scanner.py` / `async_scanner_layers.py`），由下文
「真产品代码单 case 复测」与 parity 全矩阵门复验 —— 不拿探针臂冒充
产品改动，也不拿修复后的树去改写这张带日期的对照表。

| 臂 | 替换成 2.1.0 的文件 | divergent | sync | async |
|---|---|---|---|---|
| `current` | — | **true** | sri_missing_script | + dom_dynamic/high |
| `all_210` | 全部 4 个 | **true** | 同上 | 同上 |
| `old_sandbox_pair` | sandbox.py + sandbox_parser.py | **true** | 同上 | 同上 |
| `old_sandbox` | sandbox.py | **true** | 同上 | 同上 |
| `old_parser` | sandbox_parser.py | **true** | 同上 | 同上 |
| `old_requester` | requester.py | **true** | 同上 | 同上 |
| `old_stored_auto` | scanner_stored_auto.py | **true** | 同上 | 同上 |
| **`off_fixed`** | 不改版本，两侧补 `off` 分支 | **false** | sri_missing_script | sri_missing_script |

只有 `off_fixed` 收敛。⇒ 分歧与版本无关，与 `off` 语义有关。

## 为什么 Phase 390 测到「不复现」

`phase390_parity_probe_20261114.json` 的 `pos-sri-01` 四臂
（`gate_shape` / `runner_shape` / `adaptive_off` / `budget_v2_off`）两侧都只有
`sri_missing_script`，async 耗时 0.08–0.68s —— 那次 `DynamicDomAnalyzer` 没
真正工作（构造失败被 `except Exception: return None` 吞掉，或浏览器不可用）。
`available()` 只是 `find_spec("playwright") is not None`，构造与启动在别处，
所以「Playwright 可导入」与「浏览器这次能跑」是两件事，**这确实带时基成分，
但触发开关是可修的契约，不是不可控的噪声**。

sync 侧没报 `dom_dynamic` 是因为 Phase 353 的 `_browser_pointless` 门
（外部脚本页且无静态 hint 时跳过浏览器）把它挡了；async 侧按 Phase 390
已记录的**已知设计**没有这个门。同一个「off 被忽略」的错误，一侧被
性能门掩盖、另一侧暴露 —— 典型的「同一契约手写两遍」家族。

## 契约证据

- `xssentinel/api/mcp_server.py:369-374`：input schema 的 `dom_engine`
  enum 含 `"off"`，描述白纸黑字 **"'off' disables the DOM layer"**。
- `xssentinel/core/async_scanner.py:217`：`AsyncScanner` 默认
  `dom_engine="off"`；`Scanner` 默认是 `"auto"`（CLI `--dom-engine`
  choices 为 `auto/playwright/static`，默认 `auto`）。
- 旧实现两侧 `_resolve_dom_engine()` 都只处理 `"static"` 与 `"auto"`，
  `"off"` 直接落到 `DynamicDomAnalyzer(...)` 构造。

## 修法与边界

- 两侧 `_resolve_dom_engine()` 各补 `if de == "off": return None`
  （`xssentinel/core/scanner.py:326`、
  `xssentinel/core/async_scanner_layers.py:306`）。shim 的 stored 往返
  委托同一个 async 解析器，一处定义覆盖两条路径。
- **不改** `AsyncScanner` 默认值、不改 CLI/MCP 默认值（都显式传 `auto`）、
  不改 Phase 353 的 `_browser_pointless` 门（sync-only 是已记录的设计）、
  不改判定层 / 语料 / 预算 / CLI 契约。
- **勘误（全量分批门实测推翻初稿表述）**：行为变化**不是**「只发生在
  显式要求 `off` 时」。`AsyncScanner` 的默认就是 `off`，任何**不传**
  `dom_engine` 直接构造它的调用方都走隐式 `off`，同样不再启动
  Chromium —— 全量门因此抓到 3 个真回归（见「全量分批门」一节），
  它们此前是靠「`off` 被忽略」才拿到 `dom_dynamic` 的。产品与正式
  测量入口不受影响：`cli_runner.py` 两处构造都显式
  `dom_engine=getattr(args, "dom_engine", "auto")`，MCP/REST 显式
  `auto`，`benchmark/evidence_shape_sweep.py` 显式 `static`；
  full 194 双引擎门禁验证 `auto` 路径不变。
- **未做**：CLI `--dom-engine` 的 choices 没有 `"off"`，而 MCP schema 有 ——
  这是「同一契约两处声明」的既有漂移，本轮不扩 CLI 面，记账为观察项。

## 验收

- **真产品代码单 case 复测**（本轮 `dev/_p397_sri_one.py`，`package`
  指向工作区真包）：`divergent=false`，sync / async 逐位一致
  `[sri_missing_script, medium, high]`。
- 守卫 `tests/test_phase397_dom_engine_off.py` **6 passed /
  0 skipped / 0.72s**：哨兵 analyzer 让「是否构造浏览器引擎」与本机
  Chromium 可用性解耦；覆盖 sync/async `off`、`auto` 仍构造、
  `static`/`playwright` 不变、两侧源码对称断言，以及第 6 例
  `test_dom_delivery_guards_request_the_engine_explicitly` —— 源码级
  钉住三个 DOM 交付守卫的 async 构造点必须显式 `dom_engine="auto"`，
  防止本轮真回归回潮。
- 变异 `dev/phase397_mutations.py` **2/2**：分别删 sync / async 的
  `off` 分支，各自 baseline 绿 → mutated 红 → restored 全守卫绿，
  字节级还原。
- **邻接复验**：`tests/` 下 11 个显式传 `off` 的文件 +
  `test_async_dom_live.py`（显式 `auto`）共 12 文件
  **65 passed / 0 skipped / 44.01s**。
- **parity 全矩阵门**（`XSSENTINEL_PARITY_FULL=1`）：
  **4 passed / 0 skipped / 71.49s / RC 0**。opt-in 开关确实打开 ——
  未打开时该用例会 skip 成 `3 passed / 1 skipped`，日志形状可证伪；
  396 同一门是 `1 failed / 3 passed / 1 rerun` / 358s。修复后不再
  启动 Chromium，墙钟 358s → 71.49s 是根因的独立佐证。
- **range4 双引擎** `TP2/FP0/TN2/FN0/ERR0 exit 0`（`XS_RANGE4_PORT=
  20504`）、**ruff 全仓零基线**、文档刻度与架构守卫 **28 passed**。
- **环境事件（本轮）**：`benchmark/server.py`（tracked，2704 行）在
  pytest 收集期被外部进程删除，报 `OSError [Errno 9] Bad file
  descriptor` —— 与 AGENTS.md 已记录三次的同形事件一致（来源仍未
  确认）。按既定办法 `git checkout --` 恢复；恢复后仍在读取时被删，
  加只读属性（`attrib +R`）后导入与全部门禁稳定通过。这是**本机
  环境处置**，不改产品/测试代码、不进门禁判据。
- 四档 strict gate、range3 与全量分批门数字见 CHANGELOG Phase 397
  验收节；`dev/_p397_gate_all.txt` 当时停在 `=== 7 range4 ===` 无结果，
  后续门禁由本轮补齐。

## 全量分批门：3 个真回归 + 1 个环境形态（本轮收口）

首轮（`dev/_p397_batched_gate.txt`，`--jobs 4 --quiet`，日志重定向到
工作区外）**315/319 文件绿 / 489s / RC=4**，skip **13 例 / 6 文件
（2 个整文件零贡献）**。4 个红逐个查日志，不把总数当判据：

- **3 个真回归**：`test_phase215_crawl_mined_layers.py` 2 例、
  `test_phase209_spa_route_delivery.py` 1 例、
  `test_phase214_crawl_page_layers.py` 1 例，失败信息全是
  「no browser-executed DOM finding / `dom_dynamic=[]`」，集中在 async
  臂。三者都直接 `AsyncScanner(crawl=True, ..., advanced_layers=True)`
  **不传 `dom_engine`**，用默认 `off`；而 sync 臂显式
  `use_headless=True, crawl_engine="auto"` ⇒ 这些守卫测的是 DOM 层
  交付，却一直依赖「`off` 被忽略」这个被修掉的 bug。
- **A/B 三臂**（`dev/_p397_ab_dom.py`，同一组 3 文件）：baseline
  「fix shipped」`4 failed / 10 passed`（54.8s）→ mutated「删两侧
  `off` 分支 = 修复前」`14 passed`（105.7s）→ restored
  `4 failed / 10 passed`（54.4s），字节级还原 ⇒ **FIX-CAUSED**，
  不是环境抖动，按真回归处置。
- **修法（只改测试口径，不改判定层 / 产品代码 / 断言强度）**：三个
  async 构造点各补 `dom_engine="auto"`，与 sync 臂的显式 headless
  对齐。复跑 **14 passed / 0 skipped / 105.56s**，ruff 对三文件零基线。
- **1 个环境形态**：`test_phase360_cli_compat.py` 的 `--version` /
  `-V` 两例断言 `stderr == b""`，被 `PYTHONPATH` 里 WorkBuddy shim
  的 `sitecustomize.py` 权限错误（`PermissionError [Errno 13]`）污染。
  清空 `PYTHONPATH` 单文件复跑 **34 passed / 0 skipped / 39.57s**；
  清空后 `test_async_polyglot_classification.py`（依赖靶场 server
  导入）**3 passed** ⇒ 不是靠关掉依赖换来的绿。
- **修后全量门重跑（终树）**：`dev/_p397_batched_gate_r2.txt`，清空
  `PYTHONPATH` 消除 shim 噪音后 **319/319 文件绿 / 470s /
  failures 0 / RC 0**，skip **13 例 / 6 文件（2 个整文件零贡献）**。
  首轮 315/319 与重跑 319/319 两个口径一起报，不合并成一次跑绿。
  带日期的初稿「显式 off」限定已就地更正，不保留错误表述。

## 复现

```
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
.venv/Scripts/python.exe dev/_p397_bisect.py
.venv/Scripts/python.exe dev/_p397_sri_one.py
.venv/Scripts/python.exe -m pytest -q tests/test_phase397_dom_engine_off.py
.venv/Scripts/python.exe dev/phase397_mutations.py
XSSENTINEL_PARITY_FULL=1 .venv/Scripts/python.exe -m pytest -q tests/test_parity_full_matrix.py
```
