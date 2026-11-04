# 架构与门禁（一页）

> 面向新维护者的两件事：**代码怎么组合**（契约在哪、断了谁报警）、**质量怎么守**
> （各条门禁管什么、改动后必跑什么）。操作指引见 [CONTRIBUTING](../CONTRIBUTING.md)，
> 规则与当前状态见 [AGENTS.md](../AGENTS.md)；历史论证见 `docs/archive/` 的两个归档。

---

## 1. 双流水线与 Mixin 组合契约

两条**等价**的检测流水线共享同一批判定件（`context` / `verifier` / `payloads` /
`transform` / `budget`），能力按域拆进 Mixin：

| 组合体 | 核心 | Mixin | 行数上限 |
|---|---|---|---|
| `Scanner`（sync） | `core/scanner.py` | `StoredBlindMixin`（L4 存储两步 + L5 盲打收网）· `AdvancedLayerMixin`（L3 DOM + L7/L8 高级层）· `CrawlMixin`（BFS 爬取 / 隐藏参数挖矿 / source map） | 核心 2400 / layers 1050 / crawl 550 / stored 1100 |
| `AsyncScanner`（async） | `core/async_scanner.py` | `AsyncHeadlessVerifyMixin` · `AsyncDetectionLayersMixin` · `AsyncCrawlMixin` | 核心 1600 / layers 2350 / crawl 650 / verify 145 / common 520 |
| `_AsyncScannerShim`（async 复用 sync 检测代码的适配体） | `core/async_scanner_common.py` | 复用 sync 的 `AdvancedLayerMixin` + `CrawlMixin` | common 520（同上） |

上限全部由 `tests/test_architecture_scale.py` 钉住；超限只有两条路——**拆**，或
显式抬预算并在提交信息里写明理由（这是被测量的规则，不是愿望）。

### 契约：组合体的可用面 = 全部成员的并集

Mixin 引用核心类造好的属性、核心类回调 Mixin 带进来的方法——这些链接**没有任何
语法保证**。`tests/test_mixin_contracts.py` 用 AST 把它钉住：

- 任一成员引用的 `self.X`（含 `getattr(self, "X", ...)` 字面量形态——首版漏掉它时
  全程 getattr 守卫式访问的 Mixin 被误判成"不依赖组合体"）必须在组合体并集里有定义；
- 核心类基类列表与登记一致：**新增/删除 Mixin 必须回来登记**，否则 loud fail
  （层注册两度被门禁抓到的同一课：没登记的东西从所有统计里消失）；
- 每个 Mixin 必须真的引用组合体外的名字（对它的守护才不是空转）；豁免名单
  `EXTERNAL_INJECTION` 每项必须确实无定义——把"外部注入"记成账，不开成豁免口。

这个测试抓出的第一例就是 shim 上的三处真实缺口（`_dom_engine` / `skip_params` /
`crawl_depth`·`scope`）：其中 `skip_params` 是**现行静默分歧**——async 隐藏参数挖矿
经 `shim._mine_hidden_params` 走 `getattr(self, "skip_params", None)`，空缺把操作者的
`--skip-param` 静默降级成"挖矿照挖"。处置：代理操作者意图与 L6 引擎口进 shim，
而不是让层看见空值。

### 层护栏与代价

层分发器全部挂 `core/layer_guard.run_layer()`：一层失败不杀死后续层；接线类异常
（ImportError / NameError / UnboundLocalError / SyntaxError）升 WARNING 并点名层，
duck-typing 类（AttributeError / TypeError / KeyError）留在 DEBUG 免得狼来了；
`BudgetExhausted` / `CircuitOpen` 透传（预算停止是主动结束，不是层 bug）。

**代价要睁眼看**：护栏让契约断了不会响——AttributeError 正是 duck-typing 桶里最
常见的形状。这就是上面 AST 契约测试存在的理由：语义由靶场与单测管，但"名字接得上"
是纯机械事实，不该等运行时（而且是到达那条路径时）才暴露。

### shim 的特殊地位

async 引擎复用 sync 检测代码的方式，是把 sync 的两个 Mixin 混进一个最小适配体。
它必须从 AsyncScanner **代理**进三类东西：

1. 操作者意图：`skip_params` / `crawl_depth` / `scope` / `xsleak_audit`；
2. L6 引擎口：`_dom_engine`（惰性委托 async 侧同名解析器，`static`/Playwright
   缺失时为 None，语义与 async 自己的 DOM 层一致）；
3. 共享状态：`coverage`（指向 async 的真实 tracker）、`oob` / `_oob_started`、`req`。

新增"sync Mixin 的某条路径要在 shim 上可用"之前，先跑契约测试；缺名字时按上面
第 1 类的先例补代理，并写明为什么。

---

## 2. 门禁体系（谁管什么）

门禁按"变化到被发现的距离"分层：越靠近 push 越快越小，越往右越慢越全。

| 门禁 | 入口 / 触发 | 管什么 | 防的失效形状 |
|---|---|---|---|
| **push 精度门** | CI `drills` job；本地 `python -m benchmark.runner --quick` | **64 例**分层切片（每个 `(ground_truth, context)` 族一条），双引擎 `--strict-gate`：FP0 / FN0 / ERROR0 | 判定层回归在每次 push 就红；ERROR 也算失败——没测到的用例不能让门禁"绿"得像是测过了 |
| 切片周轮转 | 同上，`--quick-offset` 由 ISO 周决定 | 最大族 49 例 ⇒ 49 次轮转覆盖全部 194 例 | 固定切片迭代几百轮后，"每次都验证过的那批"与真实矩阵脱节 |
| **全量分批门** | 每次 run 只跑一次：CI `tests`（push/PR，60min ceiling）或 `nightly-gate`（schedule/workflow_dispatch，150min ceiling），两者事件条件互补；本地 `tests/run_all_batched.py --quiet` | 逐文件 pytest，单文件 540s 预算 + 一次重试，失败/超时证据落盘 `benchmark/results/regression_logs/` | 裸跑单进程 pytest 会卡死；runner 让"一个文件挂死"只烧自己的预算；**skip 数必须与通过数一起报**——整文件 skip 的门禁什么都不曾贡献；`test_ci_no_duplicate_gate` 钉住「同一事件只有一个 job 跑门禁」，防 2026-11-04 之前 schedule run 把同一入口跑两遍（CI #18 实测 45m36s + 29m38s） |
| **行为契约靶场** | CI `drills` 的 range2–6；range7 走 `tests` job 的 pytest 契约测试 | ground truth 从**服务器行为**独立撰写的异形靶场，双引擎 100%/100% | 用自家靶自证的"满分"——靶场修复说明与 FN 复盘全部对着独立真值写 |
| **外部效度** | `benchmark-full` / 手动 | XSSMaze（第三方靶，官方 runner 与 ground truth）；跨工具同靶对照（dalfox / nuclei） | "别人出的题"只到位一半的自我认知：内部满分 ≠ 真实世界检出 |
| **结构棘轮** | 随全量分批门一起跑 | 行数上限（`test_architecture_scale`）、宽泛吞异常只许降（`test_silent_except_ratchet`）、组合契约（`test_mixin_contracts`）、文档数字 == 代码（`test_quick_gate_slice`）、F401 抑制必须带原因（`test_noqa_hygiene`）；2026-11-04 新增的 CI/文档契约守卫：`test_doc_gate_parity`（中英门禁口径同源）、`test_ci_no_duplicate_gate`（全量门禁与安装面按事件互补）、`test_dependency_audit_setuptools`（审计门不许缩窄） | 架构在无人报警时劣化（四周核心 +20%、stored +70% 的实测教训）；守卫本身空转（五种失效形状，见 AGENTS.md「工程纪律」）；同一契约被手写两遍、判定依赖量具而非被测物 |

### 证据纪律（门禁之上的门禁）

- 引用门禁数字必须来自**自己的运行**；「最新的目录」不是「我的目录」。
- **零不是通过**：`passed==0 and failed==0` 必须单列 verdict，不能落进
  `failed==0` 的分支。
- 「绿」和「跑过」是两个词：报门禁结果必须同时报 skip 数。
- 关键守卫做过**变异对照**：先断言文本存在，再变异（找不到就 ABORT），跑
  baseline / mutated / restored 三遍——只有 mutated 红且 restored 绿才算数。

### 改动 → 必跑什么（速查）

| 改了什么 | 必跑 |
|---|---|
| 判定层（上下文分类 / payload 选择 / 确认 / 评分） | `python -m benchmark.runner --quick` + `range3/runner.py --engine both` + `range4/runner.py --engine both` |
| 报告 UI / 导出格式 | `tests/test_report*.py` 系列 |
| Mixin 之间搬代码 | **搬代码与改逻辑绝不混在同一轮**；`test_architecture_scale` + `test_mixin_contracts` + 全量分批门 |
| 新增检测层 | **同时**登记 `coverage.LAYERS` 与 `layer_coverage` 矩阵（Phase 187/192 两次被门禁抓到的同一课），并补 vuln/safe 双胞胎基准用例 |
| 文档里新增数字声明 | 同步加钉（切片/矩阵类进 `test_quick_gate_slice`，行数类进 `test_architecture_scale`，其余按域进对应门禁） |
| 靠环境的行为（loopback / TEMP / 完整性标签） | 先读 `tests/conftest.py` 与 `tests/test_temp_probe_contract.py` 的 docstring，劣化期失败按「未验证」记账复跑，不当回归 |
