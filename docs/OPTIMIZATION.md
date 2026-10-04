# XSSentinel 优化方案

> 撰写时间:2026-09-30 · **修订:2026-10-01**(第 0 节数字全部重取、1.1 状态更正、
> 新增 1.0 外部效度、1.2 验收分层、3.x 事实复核)
>
> 定位:本文档是面向下一轮迭代的工程优化清单,按"投入 × 收益"排序,
> 每项给出目标文件、现状数据、改法与验收标准。
>
> **口径约定**:下文所有"行"均为 `wc -l` 的物理行(含空行与注释)。
> 2026-09-30 初版的数字是更早一次统计的残留,三个大文件偏差 100~220 行,
> 本版已按当前工作树重取。

---

## 0. 现状快照(2026-10-03 重取)

| 维度 | 数据 |
|---|---|
| 核心代码 | 119 模块 / 49193 行(Phase 191 把 async_scanner.py 拆成 5 个文件,净 +128 行全是新模块头) |
| 测试 | 151 文件 / 41361 行(用例数未按新文件重算,引用前先重跑 `pytest --collect-only -q`) |
| ruff 基线 | **0 条**(E/F/W,忽略 E501),`ruff check .` 全仓实测 |
| lint 门禁 | ① CI `ruff check`(2026-09-30 落地,fail-fast 在 tests job 之前)<br>② `tests/test_noqa_hygiene.py`(2026-10-01 落地,锁"F401 抑制必须带原因") |
| 精度 | sync 192 例 TP113/FP0/TN79/FN0,f1=1.000;async TP108/FP0/TN74/FN0(10 例 sync-only SKIP);range4 双引擎 8/8;**push 门 64 例分层切片双引擎 FP0/FN0/ERROR0** |
| 最大模块 | sandbox.py **2395** 行 / scanner.py **1737** 行 / async_scanner.py **1534** 行(拆分后)/ report.py **1428** 行 |

---

## 1. 高优先级(下轮必做)

### 1.0 外部效度:先补"能不能打赢商业工具"的证据 —— **已量(2026-10-04),但结论与本文原假设不同**
**2026-10-04 已落地(Phase 196b)**:同一批靶、三条腿、逐例矩阵 —— 见
`benchmark/results/phase196_cross_tool.{json,md}`。60 例按 `(ground_truth, context)`
分层确定性切片(60/64 族各取一条),三个工具拿到**完全相同**的目标 URL
(共用 `runner._build_target_url`,含 cookie-tossing 需要的 `sub.localhost` host 别名)。

| 工具 | 版本 | TP | FP | TN | FN | ERR | precision | recall | f1 | 墙钟 |
|---|---|---|---|---|---|---|---|---|---|---|
| XSSentinel | 本仓(14/12 预算,与门禁同口径) | 35 | 0 | 24 | 1 | 0 | 1.000 | 0.972 | **0.986** | 346s |
| dalfox | v2.13.0(Go,`go install` 经 goproxy.cn 构建) | 26 | 1 | 22 | 10 | 1 | 0.963 | 0.722 | **0.825** | 1173s |
| nuclei-dast-xss | v3.9.0 + `dast/vulnerabilities/xss` | 26 | 0 | 23 | 10 | 1 | 1.000 | 0.722 | **0.839** | 49s |

三条必须一起读的限定,否则这张表会被读成"我们赢了":
- 我方唯一那条 FN 是**打分口径**:XS-Leaks 审计层按设计给 low/firm,而这里
  "检出"定义为 high/medium/critical 的 XSS 级 finding —— 不是判定错误,也不是
  对手的优势;该层两个第三方工具根本没有。
- 靶场是**我们自己写的** 192 例矩阵的分层切片,所以"别人出的题"只到位一半:
  判定语料(nuclei dast 模板、dalfox 载荷)是第三方的,目标仍是我们构造的。
  真正的独立靶场(Juice Shop / 商业工具对跑)仍然没做。
- 速度维度我们既不是最快也不是最慢:nuclei 用 49s 拿到 f1 0.839,我们用 346s
  拿 0.986。任何"性能优于同类"的说法都要按这张表校准。

**环境复核(推翻本文 2026-10-03 那段"完全出不了网")**:GitHub API 与
`raw.githubusercontent.com` 可达;Go 模块代理 `goproxy.cn` 可达并成功构建
`hahwul/dalfox` v2.13.0;`nuclei` v3.9.0 与完整 `nuclei-templates` 早在机上。
不可达的是 **github.com 的 release 资产下载**(v3.2.3 Rust 版拿不到)与 docker/npm。
所以"dalfox 装不了"从来不是网络问题,是**没试过 Go 代理 + GOPATH 解析**
(`benchmark/adapters.py::_find_tool` 本来就查 `$GOPATH/bin`)。

**顺带量出来的尺子缺陷(已修,详见 3.7)**:预算比门禁低、目标构造丢掉 host 别名
与 per-case 旗标、子进程按 GBK 解码、错误形状只认两种 —— 首跑因此把 3 个"我方 FN"
里的 2 个记成了漏检。**如果没先修尺子,这轮会去"修"两个根本不存在的检测缺口。**



**问题**:项目的对外目标是"超越所有商业 XSS 工具",但支撑这个结论的证据
目前只有 **28 个第三方用例**(nuclei 18 + dalfox 10,且 dalfox 那次是跑在
自己的靶场上)。Burp Pro / Acunetix / Netsparker **从未对跑**;真实应用验证
近空白(只有 Juice Shop 零星几条 + 自编 Range3/Range4)。

现有的 192 例自编矩阵 sync 已满分(f1=1.000),**再加题只是给满分的考试加题**;
继续扩大自编基准不产生新的外部信息。真正缺的是"别人出的题"。

**本机结论(2026-09-30 实测,不要再试)** —— **此段已被 2026-10-04 的上表推翻,保留原文以记录它错在哪**:这台机器**装不了任何第三方扫描器**
—— 出网走代理 `127.0.0.1:17054`,ZAP 2.11.1 的 release 下载 502 CONNECT
tunnel failed(重试 3 次 + SourceForge 镜像 404)、`docker info` 失败
(daemon 未启动)、`dalfox`/`xsstrike` 本机没有、npm 的 `juice-shop` 包 2019
年已 unpublished(`git clone --depth 1` 卡住)。**跨工具对照必须换机器或换网络。**

**2026-10-02 补一条反向实测(同一段落曾被当成"什么都出不去"引用)**:出网代理
`127.0.0.1:17054` 对 **GitHub API 是通的** ——
`curl https://api.github.com/repos/cure53/DOMPurify/security-advisories` 与
`/releases/latest` 都拿到 200 JSON(Phase 189 的 DOMPurify 版本线三段区间、
CVE/GHSA 编号、latest=3.4.16 全部由此实测取得,不是记忆)。
不通的是 **ZAP 的 release 下载 / docker / npm 包**这一类。
结论要分开读:**跨工具"跑分对照"仍需换机器;厂商语料与漏洞事实不必再等网络。**

**已做的替代**:`benchmark/portswigger_corpus_coverage.py` —— 用 PortSwigger
(Burp 官方)cheat sheet 做**技术面覆盖对照**,822 条向量按 cheat sheet 自己的
分区分组,主指标只取 no_interaction 组:事件 23.1%(12/52)、标签 71.4%(15/21)、
协议 100%。三条局限已写进脚本 docstring,**别拿这个数字自欺**:字符串出现 ≠
语义等价、覆盖 ≠ 能检出、忽略浏览器支持差异。

**改法**:建第三方对照集,样本 ≥ 60 —— Juice Shop XSS 挑战全集 + nuclei 官方
DAST 模板 + ZAP(换机器跑),落 `benchmark/` 下可复现的 runner,与自编 192 例
分开记账。

**验收**:对照集 ≥ 60 例;与 nuclei 逐例结果可比(TP/FP/FN 口径一致);
结论写进 README 的对比章节,并明确标注样本量与工具版本。

### 1.1 ~~把 ruff 清零固化成 CI 门禁~~ ✅ 已完成(2026-09-30)

这条在初版里被列为"下轮必做",但落地时就在写文档的同一批里完成了:

- `pyproject.toml`:`[tool.ruff.lint] select = ["E","F","W"]`、`ignore = ["E501"]`
  (行宽刻意放行:载荷语料与报告模板天然长行),`per-file-ignores` **刻意留空**
  —— 有意豁免一律走带原因的行内 noqa,而不是全局豁免表。
- `.github/workflows/ci.yml`:tests job 之前加 `Lint (ruff E/F/W -- zero baseline)`
  → `python -m ruff check`,fail-fast。

**教训(为什么这条值得留着)**:文档 23:00 写成、pyproject 23:02、ci.yml 23:03
—— 写完没回头核对,于是把已完成项挂成"下轮必做"。**交付文档落盘前,每条动作项
都要 grep 一遍代码/CI 确认它还没被同批改动做完。**

**接续动作:防回潮(2026-10-01 已完成一半)**。清零当时靠人工,而
`per-file-ignores` 的注释声称"noqa 都带原因",实测 47 条 F401 里 **40 条是裸的**
—— 约定只存在于配置注释里。已补:40 条补原因 + 摘掉 4 条死 `BLE001`
(BLE 不在 select 内,永不触发),并新增 `tests/test_noqa_hygiene.py` 锁住
"含 F401 的抑制必须带原因"。E402 与非 E/F/W 的抑制刻意不强制(理由写在该测试
的 docstring 里)。

**剩余缺口**:`benchmark/`、`dev/`、`range3/`、`range4/` 不在该门禁范围内
(工具与靶场脚本),那里的裸 E402 与死 N802 还散着,顺手时再收。

### 1.2 ~~async_scanner.py 拆分(2881 行)~~ ✅ 已完成(Phase 191,纯移动)

实际落地时的规模已经长到 3124 行。结果:**async_scanner.py 1534 行**(编排 +
`__init__`/会话/预算 + `_probe_param` 主循环)+ 四个新模块 ——
`async_scanner_layers.py` 991(DOM/高级层/请求层/CSP/CORS/XS-Leaks/上传/JSONP/盲打)、
`async_scanner_crawl.py` 321(隐藏参数挖掘 + 端点/source map 挖掘 + BFS)、
`async_scanner_verify.py` 136(Phase 183 的 headless 确认外层)、
`async_scanner_common.py` 270(共享 helper:egress cookie jar、非 HTML 降级、
JSONP 回调名、`_AsyncScannerShim`)。

**"纯移动"是被量出来的,不是被声称的**:`dev/_p191_baseline.py` 把 42 个方法的
`inspect.getsource` 逐个哈希存档,搬完再比 —— 25 个换了归属文件、源码逐字节相同、
无方法丢失、无外部引用被断。行为侧:64 例 async 切片**逐用例** verdict 与
findings_count 与拆分前完全一致,请求数 7415 → 7415。

两点记账:
- 原提案的"核心 ~900 行"没做到,因为 `_probe_param` 一个方法就 683 行。拆它属于
  **改逻辑**,必须单独走(见 3.6 新增项)。
- 拆分让 3 个按文件路径锁定调用点的守卫变瞎(`test_async_wiring` 只读一个文件、
  `test_layer_accounting` 的 SITES 路径、`test_evidence_coverage` 的 committed 名单),
  三者都改成了"遍历 async 引擎全部模块",并各加了一条前提断言(文件数/非空/必须找到
  调用点),防止守卫退化成空转。

**实际验收(2026-10-03)**:

1. 等价性:`dev/_p191_baseline.py after` —— 42/42 方法在、25 个换归属且源码哈希相同、
   外部引用零断裂(名字被裁的每个都验证过"全仓没人从 async_scanner 拿它")。
2. 行为:`benchmark.runner --quick --engine async --strict-gate` 逐用例与拆分前
   完全一致(64 例 verdict + findings_count 全等,请求数 7415 未变),产物
   `benchmark/results/phase191_async_after_split.json`。
3. 静态层:110 例 async + 守卫 + 结构对账全绿;`ruff check .` 全仓零告警。

**未做**:全量 192 例 async 矩阵未复测(单引擎 ~25 分钟且本机 loopback 会间歇劣化),
按"未验证"记账 —— 拆分的等价性证据已经很强(逐字节 + 逐用例 + 请求数),但全量
矩阵是另一件事,合并前应手动跑一次 nightly。

**遗留(拆分之后才看得清的两件事)**:
- `_probe_param` 单方法 683 行 —— 拆它属于**改逻辑**,要单独一轮并配全量矩阵。
- 双引擎判定逻辑去重(见 2.1)不受本次拆分影响,仍是下一次的正题。

**常置规矩(不因本次完成而失效)**:一次提交只做一件事 —— 要么搬代码(纯移动,
逐字节),要么改逻辑,**绝不混在一起**。所有"async 缺了 sync 的修复"都发生在
"边搬边改"的提交里。本轮唯一一处改逻辑(`sourcemap.disclosure` 的 emit 形状)
是在等价性取证**之后**单独做的,标尺重跑即如实报出该方法哈希变化。

### 1.3 sandbox.py 拆分 —— 第一刀已完成(2395 → 1320 行)

**问题**:纯 Python 浏览器沙箱承担了"HTML 解析 + JS 模拟 + DOM 状态机"
三个职责,是评分体系的核心依赖(1680-case oracle 的对照臂),单文件
改动风险高。

**已完成(2026-10-04,第一刀:纯移动)**。走的是**兄弟模块**而不是原文建议的
`sandbox/` 包 —— 项目本来就有 `scanner.py` + `scanner_crawl.py` 这个惯例,而且
保持 `sandbox.py` 仍是模块可以让**每一个**外部 import 路径零改动:

| 文件 | 行数 | 职责 |
|---|---|---|
| `sandbox_common.py` | 136 | 两边都要的 7 个名:Node / Doc / VOID / serialize_text 等 |
| `sandbox_parser.py` | 1125 | `_Parser` + 32 个专属表与 helper(tokeniser / 建树) |
| `sandbox.py` | 1320 | 判定半边:_handler_state / find_live_nodes / judge / CLI |

依赖严格单向:`sandbox_common ← sandbox_parser ← sandbox`,无循环。

**为什么必须有个 common 层**:`_Parser` 依赖 `Node` / `VOID`,判定半边也依赖它们;
只切两半则必然出现 `sandbox → sandbox_parser → sandbox` 的环。

**三个坑(下一刀直接复用,别重踩)**:
1. **注释会被悄悄丢掉**。按定义自身的行号区间搬,会漏掉定义**上方**的 `#:` 属性注释
   —— 第一版丢了 **362 行**,而那些正是写数据来源的部分("MEASURED, not recalled
   from the spec"、"benchmark/probe_breakout.py → foreign_breakout.json")。必须把定义
   连同其上方的注释块一起搬。
2. **文件尾会被丢掉**。`if __name__ == "__main__":` 不属于任何 def/Assign,第一版直接
   删了 `python -m xssentinel.core.sandbox` 这个 CLI,**而没有任何测试发现**。
3. **分区顺序不能反**。先划 parser 再补 common,会得到"common 反向依赖 parser"
   (`serialize_text` 用到被判给 parser 的 `NO_ESCAPE_TEXT`),**运行时才**炸
   `NameError`。正确顺序:**先取 common 的闭包,再划 parser**。

**验收(已做)**:`ruff check .` 全绿;引用 sandbox 的 12 个测试文件 **174 例全过**
(与拆分前基线逐条一致);`python -m xssentinel.core.sandbox --payload ...` 实跑通过
(`state=LIVE`);`benchmark/probe_svg_case.py` 对私有名 `_SVG_ATTR_CASE` 的直接
import 仍可用 —— 它靠的是 `sandbox.py` 里带原因的 re-export,而不是运气。

**下一刀(未做)**:`sandbox.py` 剩 1320 行里还可拆出 `js_vm`(脚本体能否编译、token
落在代码还是数据串)与 `dom_state`(事件语义)。**开刀前先把这轮的搬运脚本
`dev/sandbox_split.py` 改成可指定目标的通用入口**,别再临时写一遍。

**注**:原文给出的 `sandbox/` 包 + `__init__.py` 再导出方案已被替代 —— 用兄弟模块后
根本不需要 `__init__` 再导出表,这正好省掉"重导出清单会忘记某个私有名"的风险。

**验收**:`tests/test_sandbox_fidelity.py` 8/8;`__init__.py` 再导出保持
现有 import 路径全部可用(回归测试锁)。

---

## 2. 中优先级(收益明确,可排期)

### 2.1 双引擎层逻辑去重

sync 与 async 的层实现(L7 各高级层、pre-encode、reflection profile)存在
结构性复制。历史上已发生两次"async 漏了 sync 的修复"(concat 重试、
content-type 降置信)。

**改法**:把纯判定逻辑(无 I/O)下沉为共享纯函数,引擎只保留 I/O 差异。
候选:`_grade_evidence` 已共享,下一步是 `_non_html_grade`(目前
async_scanner 内部复制了 scanner._record 的逻辑)。

**验收**:共享函数抽出后,177 Phase 那类"双引擎漂移"在结构上不可能发生;
每次下沉都要补一条"双引擎同输入同输出"的 parity 测试(项目已有
`test_async_*_parity` 系列,沿用其写法)。

### 2.2 报告层性能

[report.py](file:///d:/qoder/xssentinel/xssentinel/core/report.py) **1428 行**,
六格式共存的字符串拼接在大 finding 数(>500)下会成为瓶颈。

**改法**:HTML 构建从 f-string 拼接改 `list.append` + `"".join`;
大报告 benchmark 化(`benchmark/` 加一例 1000-finding 合成负载)。

**验收**:1000 findings 的 HTML 生成 < 2s(**当前未测量,先建基准**——
没有基线就别谈"优化了多少")。

### 2.3 靶场覆盖扩展

range4 已覆盖 React/Vue 双框架,但 **Angular / Svelte / Lit 只在语料层
覆盖,没有真实框架靶场**。已知框架 sink 检测有 framework_xss.py,缺
端到端验证。

**改法**:range5,vendored Angular 发布版 + 对应 `-safe` 双胞胎,
沿用 range4 的"构造效度先行"流程(先证对照页服务端 HTML 不含 attacker
字符串,再开评分)。

**验收**:同 range4 门禁语义(FN/FP/ERROR ⇒ exit 1)挂 CI。
**构造效度是硬前置**:range4 首版就栽在"安全对照页"自己也反射进服务端
JS config line(那本身就是 script-string sink),四例全 confirmed、safe
双胞胎被判 FP —— **错的是靶场不是扫描器**。

---

## 3. 低优先级(顺手做)

> 2026-10-01 复核:以下三条清单**均属实**,3.2 的实际问题比初版写的更重。
> 2026-10-04 复核:3.1 / 3.2 已做完(见下),3.3 只剩 SECURITY.md 联系方式
> 这条——它必须由仓库归属者填,agent 不能替 maintainers 编一个邮箱或表单。

### 3.1 ✅ 死代码清理 —— 已完成(2026-10-01)

- `tests/test_param_miner.py::_crawl_self`(原第 300 行)— **已删**。它是重构
  残留:同一个类里两个真实测试各自内联构造 fake,全库零调用方;删后
  `tests/test_param_miner.py` 21 例全过。
- `tests/_test_coverage_demo.py` → **`dev/coverage_demo.py`**(git mv)。确认无
  CI 引用(CI 走 `pytest tests/`,下划线前缀本来就不被收集)。顺手把它的端口
  **8898 → 18456**:8898 正落在 Windows 保留段 8810-9109 里,而项目的端口
  约定已是 18xxx 段。
- `dev/verify_*_20260902.py`(3 个)→ **`dev/attic/`**。全库无引用。

### 3.2 ✅ 依赖治理 —— 已完成(2026-10-01)

原描述把问题写轻了(只说"版本漂移"),实际是**语义不一致**:`requirements.txt`
把 aiohttp / playwright / flask / esprima / pytest* 全部平铺成必装,而
`pyproject.toml` 是 core 3 个 + `[project.optional-dependencies]` 分组 ——
两条安装路径装出来的环境根本不是同一种(按 requirements.txt 装会连 dev 测试
依赖一起装上)。

**已改为单行委托** `-e .[dev,async,ast,api]`,版本约束只留 pyproject 一处;
文件顶部写清了"为什么这里不再手列包"。比原建议的 `-e .[dev]` 多带三个 extra,
是为了与**旧文件的实际安装结果等价**(旧文件确实装了 aiohttp/flask/esprima),
避免这次治理顺手把别人的环境降级。**刻意不含 `headless`**:playwright 还需要
`playwright install chromium`,CI 与 README 都把它当独立可选步骤。

**验证**(不是"看起来对"):`pip install -r requirements.txt --dry-run` 能解析到
`Would install xssentinel-1.0.0`;四个 extra 名与 pyproject 逐字核对无缺失。

**一处更正**:本条原文说"README 的安装段落同步(它现在两种装法都在教)"—— 实测
不成立。README 安装段只有 `pip install -e .` 加独立的 playwright 步骤,
**全文从不提 requirements.txt**,因此本次没动 README。

### 3.3 文档

- `SECURITY.md` 的举报联系方式仍空缺("联系方式待补充"),**仓库归属者需填写**
- CHANGELOG:`Unreleased` 段已于 2026-10-01 补起,现已记到 Phase 197;
  后续仍需每次改动顺手记

---

## 3.5 Phase 189 复核(2026-10-02):本文档自称的"待做"有两条早已做完

按本文档自己定的规矩("每条动作项落盘前 grep 一遍代码确认它还没被同批改动做完"),
复核结果:

| 条目 | 文档说法 | 实测 |
|---|---|---|
| 3.1 死代码 `tests/test_param_miner.py::_crawl_self` | 待清 | **已清**(工作树里 grep 零命中);`_test_coverage_demo.py`、`dev/verify_*_20260902.py` 也已 git mv |
| 3.2 requirements.txt 双源语义不一致 | 待改 `-e .[dev]` 委托 | **已改**(`requirements.txt` 现在就是一行 `-e .[dev,async,ast,api]` + 为什么不手抄的解释) |
| 竞品可借鉴"退出码四态分离" | 未记 | **已有**:`__main__.py` 的 0 / 1(达到 `--exit-code` 阈值) / 3(本次运行不支持否定结论)三分 |

**教训同 1.1**:清单写于 2026-10-01,当天下午的改动就把其中两条做完了,而文档没有
回头核对 —— 下轮再引用本文档时,先跑一遍每条动作项的 grep。

## 3.6 Phase 189 新增待办(按投入 × 收益排序)

1. ~~**`--stop-at-cross-origin`(授权边界,默认关)**~~ **已做(同日续)**:规则从"剥凭据"
   升级为"不投递载荷",经 `Session.resolve_redirects` 不 yield 实现;CLI 端到端实测
   关=40+ 探针落到第三方源、开=0。剩余不对称:aiohttp 跳转循环在 `_request` 内部,
   `on_request_redirect` 改不了下一跳目标(实测),故 async 只做到剥凭据 ——
   真要让 async 也停,得把 async 的取页路径改成手工跳链(20 余个 `session.request`
   调用点),投入产出不匹配,除非有真实需求。
2. **`'unsafe-hashes'` 从"检出"走到"利用"**:Phase 189 只在 `analyze().weak` 里点名
   `unsafe-hashes` 可以让 hash 授权 `on*` 属性,还没据此选 payload。表内 hash 是
   页面自带脚本的 hash,不是我们能控制的反射值 —— 真要利用需要"反射内容恰好等于
   某条已声明 hash 的前缀"这类条件,先做可行性测量再决定,别写投机逻辑。
3. **SSR hydration state 作为污点源**(`__NEXT_DATA__` / `window.__NUXT__` /
   `INITIAL_STATE`):Phase 189 评估后**决定不动**。理由:端点挖矿侧它已经被
   `js_miner.INLINE_SCRIPT_RE` 覆盖(JSON 里的 `"path": "…"` 走的正是同一个
   extractor),而把它加进 DOM 污点源列表会改变判定语义 —— 服务端渲染进 hydration
   blob 的数据是否攻击者可控,静态层面判不出来。要做就得按 176i/176j 的路子先给
   Chromium oracle 造出"可控/不可控"对照页测量,再决定接不接。竞品(nexa/ASTra)
   只把它当**提取源**,不当漏洞证据,这个尺度是对的。
4. **净化器层没有独立靶场**:Phase 189 的 DOMPurify 配置面检测靠语料 + 单测,
   没有 range5 那种"真实 sanitizer + 真实绕过"的端到端门禁。mXSS 家族已有
   `mxss_verify.py` 与浏览器 oracle,可优先考虑把 sanitizer 配置面并进同一套
   range 流程(先做构造效度)。
5. ~~原有 1.2(async_scanner 拆分,现约 2960 行)~~ **已完成(Phase 191,纯移动 +
   逐字节/逐用例取证,见 1.2)**。剩余不变:1.3(sandbox 拆分)/ 2.1(双引擎
   判定去重)/ 2.3(range5 框架靶场)/ 1.0(第三方对照集,需换网络)。
   新增一项:**1.4 `_probe_param` 拆分**(683 行单方法)—— 它属于**改逻辑**,
   验收要配全量 192 例矩阵,不能和纯移动混做。

---

## 4. 明确不做

| 事项 | 原因 |
|---|---|
| 清理 Mixin 的 `noqa: F401` 标记 | 运行时引用是 Mixin 架构的有意形态;现在的规矩是"必须带原因",不是"必须删掉" |
| 全量类型标注(mypy strict) | 111 模块体量下投入产出不匹配;保持 `test_no_undefined_names` 的 pyflakes 门控即可 |
| 重写 async 引擎为纯 asyncio 解析 | BS4/lxml 无 async API,`asyncio.to_thread` 是正确折中 |
| 引入重型 ORM/数据库 | range3 证明 SQLite 足够;API 持久化当前无规模压力 |
| 继续扩充自编 192 例基准 | sync 已 f1=1.000,边际信息为零;要新信息就去建 **1.0 的第三方对照集** |

---

### 3.8 观测记录:async 每条响应的线程 CPU(2026-10-04 剖析得到,未优化)

补 async HPP 体位测试时顺手量到的事实,记下来免得下轮重新猜:

- 一条 `_probe_param` 走完后总耗时 ~55s,而 **20 个请求全部在毫秒内发出**
  (在桩 session 里打时间戳测得 gap 合计 ≈ 0.4s),`asyncio.sleep` 调用数为 **0**。
- cProfile 的累积时间几乎全在 `GetQueuedCompletionStatus`(IOCP 等待),
  主线程只见等待不见计算 —— 因为真正的工作在 `asyncio.to_thread` 的线程里,
  **cProfile 默认不跟线程**。收缩 `max_payloads` 3→1 只把 55.2s 降到 54.7s,
  关沙箱门(`XSS_SANDBOX_GATE=0`)降到 50.1s:说明成本不在载荷条数也不只在沙箱。
- 结论:这是**每响应的判定 CPU**,不是测试人为成本 —— 与门禁里 async 单例
  ~5s 的量级一致。值得作为性能项单独量:先建"每响应判定耗时"基线
  (线程内计时,不是 cProfile 总时间),再谈优化;优化前不要被
  "测试很慢"引导去删测试。
- 处置:新测试保留两条必须分开跑的用例(体位确认 + 取首值反例),
  query 位的 `param_in` 断言并入既有那条 async HPP 测试(零额外耗时)。

### 3.7 Phase 196b 新增待办(按投入 × 收益)

1. **async 引擎看不见 `<meta>` CSP**:sync 侧已把阻断判定接到 header + meta 两条
   通道,`async_scanner_layers._scan_csp_async` 签名里仍只有 headers。补它需要
   在调用点(`async_scanner.py`)把页面 body 传进来 —— 本轮那个文件是另一路的
   在制品,没动。异步的**判定**(verifier 链)已共享,所以缺的只是 L7 报告层。
2. ~~**DOM sink 面缺口(dalfox v3.2.0 对位)**~~ **已实测并部分闭合(Phase 197)**:
   `dev/_p197_sinkoracle/probe_sink_oracle.py` 把每条候选形状在真 Chromium 里用可归因源
   (`location.search` / `location.hash`)跑一遍,同时问我们的引擎在同一页看见什么:
   `setAttributeNS(null,'onclick', attacker)` **执行**且我们**看不见**(DOM 通道只 hook
   `setAttribute`)→ 已补 hook,`tests/test_phase197_dom_sinks.py` 双层(纯断言 + 活体
   端到端)并带变异对照(摘掉 hook 后活体命中集合变空)。
   `var f = eval; f(x)` 与 `window['eval'](x)` **执行且已命中**(hook 替换 `window.eval`
   之后别名读到的就是包装函数)——不是缺口。
   `document.parseHTMLUnsafe(attacker)` 再 append 进文档 **不执行**;
   `dataTransfer` / `navigator.clipboard.readText()` 的源扫描器不可归因
   ——这三类**刻意不加**:加了就是替浏览器否认的形状背书。
   剩余真待办只有一个:`FileReader.onload → innerHTML`(Blob 源)执行且当前只在
   `innerHTML` 这一跳被看见,源侧没有 FileReader 建模 —— 属污点源建模,需按 176i/176j
   的路子先造可控/不可控对照再动,不当作本轮已完成项。

3. **对照产物的 scoring 口径应进产物本身**:`benchmark/adapters.py` 里"检出 =
   high/medium/critical 且 type 不以 `csp_` 开头"是硬编码在解析逻辑里的;
   应写成 `run_cross_tool.py` 输出中的 `scoring` 字段,让 JSON 自己说清口径。
4. **`flask.app.test_client()` 在本机不可用**:装的 Werkzeug 已移除
   `__version__`,而 Flask 2.2.5 的 `EnvironBuilder` 要读它,于是 `test_client()`
   在建请求前就抛。`tests/test_phase196_api_gate.py` 改用 `werkzeug.test.Client`
   直接驱动同一个 WSGI app(测的是真路径),但这是一条**环境漂移**,依赖治理
   (3.2 那一族)应把 Flask/Werkzeug 组合钉住。

## 5. 执行顺序建议

```
已完成: 1.2 async 拆分(Phase 191)/ 1.0 外部效度对照(Phase 196b,60 例三工具同靶)
已完成: CSP 投递通道判定(header+meta、report-only 不再冒充保护)/ API 前端门对齐(196b)
本轮:  1.0 (外部效度对照集 -- 唯一能支撑对外目标的证据;需换机器)
下一轮: 1.4 _probe_param 拆分(683 行单方法,属改逻辑,验收配全量矩阵)
再下轮: 1.3 sandbox 拆分 → 2.1 双引擎去重 → 2.3 range5
顺手:  3.x 随对应模块改动时一并处理
```

每一项的验收标准都已给出,**1.0 之外全部可离线验证**(测试命令或 ruff 退出码)。
1.0 是唯一依赖外部环境的项,也是唯一能回答"到底超没超越商业工具"的项
—— 它不该因为"麻烦"被无限期推后。

**2026-10-03 环境复测(别把上面那段当成常驻事实)**:本机现在**完全出不了网**
—— 代理 `127.0.0.1:17054` 无监听(netstat 空),直连 `raw.githubusercontent.com`
curl exit 28。上面"GitHub API 是通的"那条反向实测写于 2026-10-02,已过期。
结论:1.0 的可执行性**逐日变化**,每次开工前先 `curl -m 10` 复测,不要引用旧条目。
