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

## 0. 现状快照(2026-10-05 重取)

| 维度 | 数据 |
|---|---|
| 核心代码 | 122 模块 / 50396 行(2026-10-05 实测;含 Phase 193–197 与 sandbox 首刀拆分) |
| 测试 | 229 文件(全量套件实测,2026-10-23);`pytest --collect-only -q` = **3495 用例**(引用前先重跑,别抄这里的数字当活数) |
| ruff 基线 | **0 条**(E/F/W,忽略 E501),`ruff check` 全仓实测 |
| lint 门禁 | ① CI `ruff check`(2026-09-30 落地,fail-fast 在 tests job 之前)<br>② `tests/test_noqa_hygiene.py`(2026-10-01 落地,锁"F401 抑制必须带原因") |
| 精度 | sync 194 例 TP113/FP0/TN81/FN0,f1=1.000;async TP107/FP0/TN75/FN0(12 例 sync-only SKIP);range4/5/6 双引擎全绿;**push 门 64 例分层切片双引擎 FP0/FN0/ERROR0**;外部 XSSMaze client 24/0/0、server 925/88/0(控制例 FP 0,Phase 307) |
| 最大模块 | scanner.py **1869** 行 / async_scanner.py **1618** 行 / __main__.py **1511** 行 / dom_engine.py **1455** 行 / report.py **1440** 行(sandbox.py 已拆为 sandbox 1320 + sandbox_parser 1125 + sandbox_common 136) |

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
- 靶场是**我们自己写的** 194 例矩阵的分层切片,所以"别人出的题"只到位一半:
  判定语料(nuclei dast 模板、dalfox 载荷)是第三方的,目标仍是我们构造的。
  真正的独立靶场(Juice Shop / 商业工具对跑)仍然没做。
- 速度维度我们既不是最快也不是最慢:nuclei 用 49s 拿到 f1 0.839,我们用 346s
  拿 0.986。任何"性能优于同类"的说法都要按这张表校准。

**2026-10-24 补上"别人出题"的一半**:独立靶 XSSMaze v0.3.0(dalfox 作者维护,
官方 runner,ground truth 来自靶自身 `/map/json`,27 条 `exploitable=false`
控制例)终态 —— client 群 **TP24/FN0/FP0**(P/R/F1 1.000)、server 群
**TP925/FN88/FP0**(P 1.000 / R 0.913 / F1 0.955,Phase 307),**控制例 FP 0**。
4 条 100s wrapper 超时在单独复跑里 10–12s 完成并命中(环境),补齐口径
**929/84/0**(R 91.7% / F1 0.957);Phase 306 的 920 也含 3 条超时(本轮恢复)。
目标、答案键与评分器都是第三方的,补上了"靶场是我们自己写的"这一半;
仍缺的是与商业工具在同一独立靶上的对跑。口径与已知限制见 README「外部效度」。

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

现有的 194 例自编矩阵 sync 已满分(f1=1.000),**再加题只是给满分的考试加题**;
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
DAST 模板 + ZAP(换机器跑),落 `benchmark/` 下可复现的 runner,与自编 194 例
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

**下一刀:量过了,不做**(2026-10-04 测量,别再把这条当待办)。两条轴线都试过:

1. **按职责切 js_vm / dom_state —— 切不动**。给 `_js_parses` / `js_state_at` /
   `_script_candidate` 做 js_vm 种子,`_handler_state` / `_smil_state` 做 dom_state
   种子,算闭包后:orchestration(`judge` / `find_live_nodes`)的闭包吞掉了剩余
   **46 个顶层名里的 43 个**,且依赖是**双向**的 —— `js_vm ↔ orchestration` 各 3~4 处、
   `dom_state ↔ orchestration` 各 3~4 处。硬切只会得到循环导入,或一堆跨模块回调
   把"拆开"变成"更难读"。
2. **按"常量表 vs 逻辑"切 —— 能切但不划算**。剩余的 22 个顶层 Assign **全是纯数据**
   (100%,没有一个在赋值里调用本模块函数),可无风险搬走,但只有 **113 行**,
   `sandbox.py` 1320 → 1207(-8.6%),代价是多背一个文件。

**结论**:剩下的 1320 行是一个**高内聚的判定核心** —— 事件语义、JS 状态、token 是否
落在可执行调用里,这些判定本来就是互相引用的。1.3 的收益在第一刀已经拿到
(2395 → 1320,-45%),继续拆是把高内聚的东西强行拉直。**本条结项**,精力转回
1.0 外部效度与 2.1 双引擎去重。真要再动,前提是先把判定逻辑本身的耦合解开
(那属于改逻辑,不是搬家,得配全量矩阵验收)。

**注**:原文给出的 `sandbox/` 包 + `__init__.py` 再导出方案已被替代 —— 用兄弟模块后
根本不需要 `__init__` 再导出表,这正好省掉"重导出清单会忘记某个私有名"的风险。

**验收**:`tests/test_sandbox_fidelity.py` 8/8;`__init__.py` 再导出保持
现有 import 路径全部可用(回归测试锁)。

---

### 1.5 JS bundle 被当成"页面"扫 → 真实靶上 3 条 high 假阳性(2026-10-09 量到,**三类病因已各自改掉**,Phase 210b)

> **原判读需要更正两处**(写完才实测的代价,按本项目 1.1/3.5 的同一课回头核对):
> ① 不是"3 条"而是 **5 类 8 条**:`discoveronly2` 那次跑还给了 4 条
> `trusted_types_no_policy`(medium)与 1 条 `framework_angular_xss`(high),
> 全部落在 `.js` URL 上;原文只数了 high,把音量当数量读了。
> ② `open_redirect_xss` 的病因不是"层太宽松",而是**判定窗口自引用**:
> Phase 113b 遮了赋值式的左手边,但调用式(`window.location.replace(`)没有左手边,
> 且固定 200 字符尾窗**伸进下一条语句** —— 压缩包里下一条通常又是同一个 sink。
> 所以它是 113b 的**没修完**,不是一个新类别。

**实测对象**:OWASP Juice Shop 20.2.0,`--discover --headless`(不带 `-c`)。
报告给出 4 条 high,其中 3 条落在 `main.js` 上、`evidence_class=browser-unavailable`、
**`proof` 为 None**(读者无从核对):

| 报告的 claim | bundle 里实际是什么 |
|---|---|
| `postmessage_xss`:"vulnerable postMessage listener: `setTimeout(string) from postMessage payload`; no origin check" | `main.js` 里 **`addEventListener('message'` 出现 0 次**;37 处 `setTimeout(` 传的都是函数(`setTimeout(()=>{n.classList.remove(i)},1e3)`、`setTimeout(this.dispose,500)`) |
| `websocket_xss`:"onmessage handler feeds event.data into a dangerous sink" | 同上 —— 判定形状是 "`setTimeout(` 后面跟了个标识符" 就当字符串实参 |
| `open_redirect_xss`:"DOM redirect sink fed by user input `location.replace(<user input>)`; params=['to','redirect_uri']" | 5 处 `location.replace(` 全是硬编码常量:`window.location.replace(L$.hostServer + \`/profile\`)` |

**为什么 fixture 永远测不到**:本仓靶场从不把 `.js` 当扫描目标交付
(benchmark 的 JS 用例是给 `L9_js_miner`/`L8_framework` 的**语义**用的),
而 `--discover` 的 `resource_urls` 天生包含 `main.js`/`scripts.js`/
`rolldown-runtime-*.js` —— 真实 SPA 一渲染就是一堆 chunk。
Phase 210 把"probeable 优先"的排序修好后,这个面**暴露得更充分了**
(同一次跑里 JS chunk 从 1 个变 3 个),所以这是必修项而不是边角。

**这不是"降级就完事"**:三条里至少 `framework_angular_xss` 一类是真实存在的
检测面(Juice Shop 确实有 Angular sink),问题在**证据与档级**:
`browser-unavailable` + `proof=None` + `severity=high` 三者同时出现,
等于"最弱的证据配最高的音量"。修法必须按本仓老规矩:
1. 先造对照 —— 同一个 sink 形状在**可控/不可控**两版 bundle 上跑,
   看层能不能区分"`setTimeout(fn)`"与"`setTimeout(string)`"
   (Phase 196b 的 CSP 投递通道五形态矩阵是同款方法论);
2. 判定改动要有门:若定"无浏览器证据 + 无 proof ⇒ 至多 medium/low",
   就要有测试锁住,并复跑全量矩阵确认没把真阳一起降掉;
3. 每条静态层都应带可核对的 `proof`(文件 + 偏移 + 片段),
   `proof=None` 本身该被门拒绝 —— 交付面上"不可核对的高危"是最贵的一类错误。

**已落地(2026-10-09,Phase 210b)—— 按三类病因各改各的那一处,不是一个通用降级**:

| 病因 | 改法 | 对照与门 |
|---|---|---|
| 判定谓词**声称了它没测的性质**(`setTimeout(` 后跟标识符 ⇒ "string") | 共享谓词 `core/string_eval_sinks.py`:先认回调形状(`=>`/`function`/`}`),再认字符串/拼接/`data`;裸标识符**故意不判**,并把这条权衡钉成测试(`test_bare_identifier_is_deliberately_not_claimed`) | `tests/test_phase210_string_eval_sinks.py` 9 例;两条旧宽松模式从 `DANGER_SINKS` 删掉并留注释,**AST 常量级**门防"修一个忘一个" |
| 判定窗口**自引用**(sink 自己给自己作证) | ①遮罩含黏在前面的 `window./self./globalThis.` 限定符;②遮罩窗口内**所有** sink 跨度;③判定区收窄为**该 sink 自己的语句**(调用式到配对右括号;赋值式到 `;`)。RHS 全留:模式里的 `[^;\n]` 会吃掉 `location.hash` 的那个 `l`,整段遮罩会误杀真阳 | `tests/test_phase210_redirect_selfsource.py` 9 例(含样本表 ↔ `DANGER_SINKS` **双向**覆盖);bundle 级取证 `dev/redirect_selfsource_probe.py` 用 `git show HEAD:` 取旧模块当对照组,同一批 28 个真实 JS 文档双臂跑:**HEAD 6 条 exploitable → 现 0 条**,真阳 fixture 两臂都报,且**逐条打印被删项供归因**(数量不是结论,读得通才是) |
| **文档种类从来不是判定输入** | 新增 `core/document_kind.py`(媒体类型优先、URL 后缀兜底;`.js` 答 `text/html` 判为页面)。`tt_no_policy` 在脚本上**不发**(它读的是页面的 CSP,脚本响应没有);`taint_flow`/`policy_bypass` 读代码 → 保留。框架模式在脚本上**降 low/low + "no page context"**(线索留着,音量撤掉) | `tests/test_phase210b_script_documents.py` 9 例,含**反向对照**(同一文本作为页面必须照旧报)与 dispatch 契约门:AST 读出 `run_page_layers` 每条 `run_layer(...)` 的实参数,`inspect.signature().bind()` 逐个核对 —— 防"层签名漂移 + TypeError 被 per-layer guard 吞成 DEBUG"(Phase 63/84/198 三次同一形状) |

接线只有一处:`run_page_layers()` 是双引擎唯一的页面层入口(sync `scanner.py:556` /
async `async_scanner_layers.py:245` 经 shim),而它本来就要为 CSP 判定再取一次响应头,
`content_type` 就在那儿读 —— **零额外请求,且两个引擎不可能不同步**。

**变异对照头两次跑都报 `guard_is_load_bearing=False`**(`dev/phase210b_mutation_control.py`):
M1 的锚点选在 `_statement_end()` 的**赋值式分支**,而真实靶走**调用式分支**
(与 `dev/_MUTATION_CONTROL_LESSON.md` 同课,只是这次错在分支不是缩进);
M2 更值钱 —— 遮掉"邻居也算"的循环后我的样本**仍然全绿**,因为语句边界已挡住那对兄弟;
缺口是"邻居落进 60 字符**前瞻**窗口"这个形状没被样本覆盖。补
`switch(r){case 1:location.href="/a";break;case 2:window.location.replace(h+\`/b\`)}`
之后 M1/M2 双双变红。
**M5 是同一个形状的第二遍**:把 dispatch 里 `content_type` 的读取打回大小写敏感的
`_hdrs.get("Content-Type")`,五项**全部仍绿** —— 因为测试用的是 `http://h/main.js`,
大小写一丢就落进 **URL 后缀兜底规则**,两条路径给出同一个答案。改成无扩展名的脚本路径
(`/assets/dynamic-bundle`,只有响应头能说明它是脚本)之后 M5 才变红,并据此发现
**兜底规则确实掩盖了一个真缺陷**:`_hdrs` 是从 CaseInsensitiveDict 复制来的**普通 dict**,
大小写敏感取法在代理重写头之后就失效(现按 `k.lower()=="content-type"` 取)。
五项最终全部 `mutated_red=True / restored_green=True` + 逐字节还原自校验。

**"守卫声称防 A,实际测 B"本项目已记到第五、六次,来源都是同一个**:
测试的输入没能把"实现对"和"实现错"分开。**先问什么输入能区分两者,再写断言** ——
而不是写完断言看它绿了就收工。

**仍然待做(原文第 2、3 条的一般形式,本轮没动)**:
① 静态层一律 `proof=None` —— "不可核对的高危"该被门拒绝,这需要跨**全部**静态层的
证据形状门;② "无浏览器证据 + 无 proof ⇒ 至多 medium" 的**通用**降档规则,需要自己的
对照矩阵与全量矩阵复测。现在只是按每种错各自的证据改了各自那一处 ——
**把它们合并成一条通用规则听着更省事,但那正是本项目反复记账的"用信念代替推导"**。

**关联**:与 1.0(外部效度)、2.1(对等门)同源 —— 都是"实验室指标掩盖了
真实世界的形状"。Phase 209 的模板 SSTI 假阳性是同一种病的另一个器官
(把栈行号 `route.js:149:13` 里的 `49` 当成 `{{7*7}}` 的渲染结果)。

## 2. 中优先级(收益明确,可排期)

### 2.1 双引擎对等:不是"去重代码",是"锁住行为"

> **原文假设已被实测推翻(2026-10-05)**,下面的改法已按实测重写。

**实测**:两边 ≥6 行的函数共 sync 81 个 / async 50 个,**同名仅 4 个**,内容完全一致的
只有 1 个(`_suppressed`),文本相似度 ≥0.75 的平行实现只有 2 对(`_suppressed`、
`_resolve_dom_engine`)。**几乎不存在函数级复制** —— 两边早就各自演化了。

那历史那两次事故(177 的 concat 重试、178c 的 content-type 降置信)到底是什么?
**不是"复制的代码忘了同步改",而是"一边有某个分支、另一边根本没有"** —— 是行为
不对等,不是代码重复。所以原文"把纯判定逻辑下沉为共享纯函数"这条路会扑空:
没有多少可抽的东西(`_grade_evidence` 已经共享了,这是早就做完的部分)。

**真正的改法**:把 parity 从"出一次事故补一条"变成系统性的门。现有 5 个 parity
测试文件共 **15 例**(`test_async_param_stage_parity`、`test_async_phase196_hpp_body_parity`、
`test_coverage_matrix_parity`、`test_csp_nonce_async_parity`、`test_layer_registry_parity`),
全都是**点状**的 —— 每条对应一个具体修过的 bug,而不是"同输入 → 同输出"的通用门。
事故每发生一次,门才补一条;没发生的那一类,门就是空的。

**候选做法(未做,开工前先估成本)**:同一组输入分别走双引擎,逐字段比对产物
(type / severity / confidence / param / 证据词),差异即失败。**难点不在写断言,
而在先钉死"可比"的定义** —— async 的请求调度与重放顺序天然不同,必须先约定比较
的是"finding 集合的规范化形式",否则这条门会天天红、然后被关掉。

**验收(关键)**:新门必须能**复现历史那两次事故** —— 把 async 的 concat 重试摘掉、
把 async 的 content-type 降置信摘掉,门必须红。**不能用"跑通就交差"**:一个
抓不到已知事故的门,等于没有门(这条教训在 pyflakes 门禁那次已经付过一次学费,
Phase 222 又付了一次 —— 见 2.1.2 的假绿)。

> **已闭合(Phase 222,见 2.1.2)**:门从 24 个手挑端点扩到 manifest 全 194 例
> (182 例可比),测量结果 182 例 **0 分歧**,并当场抓到 1 处真缺陷
> (`csp_bypass` 缺 confidence)与 1 处我自己造的假分歧(两侧入口点不对齐)。


> **DOM 家族扩容已落地(2026-10-06,Phase 203)**:manifest 的 12 个 DOM 端点
> (6 阳性 + 3 safe 孪生 + 原型污染对)以 dom_engine="auto" 入门 —— 动态引擎
> 代码共享,但层接线(sync `_scan_dom` vs async Phase-65 路径)正是事故高发区。
> 首次尝试的"空对空"结论是用错靶场服务器所致(vuln_server 的 /dom 打到
> manifest 服务器 → 404 页对比),静态网本身没坏(dom.analyze 在
> eval(URLSearchParams.get) 形状上正常命中)。harness 教训:dom_engine="auto"
> 的 sync 扫描会让 Playwright 把 asyncio loop 绑到测试线程,async 半场必须
> 跑在独立线程。**已落地(2026-10-05,`tests/test_engine_parity_gate.py`)**:12 端点反射切片
> 双引擎同预算对跑,比较 (type, severity, confidence) 有序多重集 —— context
> 排除已被实测论证(同一参数多向量时"哪个 payload 先确认"是梯子顺序问题,
> /s/flt05 上 sync 确认 concat-stamp svg、async 确认 javascript:-URI,皆为真)。
> **验收双向通过**:monkeypatch 摘掉 async 的 content-type 降置信(178c 事故)
> 与 concat 重试(177 事故),门各自变红。**门落地的当天就抓到第一类新分歧**:
> async 的 L7 层 shim findings 视图缺主循环裁定,polyglot fallback 只在 async
> 误发(/r/jsonct01 多一条)—— 已修(shim seed + param_confirmed 哨兵),顺带
> 修复两个引擎 polyglot finding 缺 confidence 键的报告元数据缺陷。

#### 2.1.1 实测新分歧(Phase 209,2026-10-09):async **发现端点但不检查它们**

真实靶场(OWASP Juice Shop 20.2.0)第一次把这条暴露出来 —— 本仓 194 例矩阵与
range3/4 都是**逐端点显式给 URL**,爬取到的端点从未成为 DOM 判定的对照对象,
所以这一类"一边整个分支不存在"的门是空的:

| 跑法 | 结果 |
|---|---|
| `sync -u <origin> -c --headless` | 1 条 `dom_dynamic` high/high **browser-executed**(`location.hash` → `Element.innerHTML`),即上游 `localXssChallenge` |
| `async -u <origin> -c --headless` | **0 findings**,374 请求,0 失败 —— 端点确实被发现(`_crawl_mine_endpoints` 直调返回 `/#/home?v=xss`),但没有被检查 |
| `async -u <origin>/#/search?q=apple --headless` | 1 条 high/high browser-executed,12 请求 |

**代码依据**:`async_scanner_crawl.py:344,378` 对爬到的端点只调
`self._scan_reflected(...)`;而主循环 `_scan_raw`(`async_scanner.py:578-612`)
为端点建 L1 + `L3_dom`(`_scan_dom_async`)+ `L5_advanced_page` + `L8_request`
全套 page_tasks。sync 侧 `scan_target` 对爬到的每个端点都走完整流程 —— 所以
**async 的爬取等于"只跑反射层"**。三条 parity 门都测不到它,因为它们喂的是显式
端点,不是爬取产物。

**当日已修(fragment 路由这一支)**:`_crawl_and_scan` 对带 fragment 的端点改跑
`_scan_dom_async`(并纳入 `mined_seen` 去重,否则同一路由从内联与外链 JS 各发现一次
会付两次浏览器),`m_base` 的 `split("?")` 不再截掉 fragment 内的 query。
复测:`--async -u <origin> -c --headless` 在真实靶上给出 1 条 `dom_dynamic`
high/high **browser-executed**(`#/track-result?id=`,与 sync 命中的 `#/search?q=`
是**两个不同**真实 sink);两路由均经独立 Playwright 复核:注入
`<em class="xssprobe9k">` 后 `querySelectorAll('em.xssprobe9k').length == 1` 且
页面不把它显示成文本 —— parsed,不是 escaped,sink 为真。
门:`tests/test_phase209_spa_route_delivery.py` 现按 **双引擎** 参数化
(阳性 + safe 孪生 × sync/async),变异对照(摘掉 `_crawl_spa` 的 merge)必红。

**仍然开放的更大一支(Phase 222 已闭合)**:async 爬到的**非** fragment 端点
仍只跑反射层(`async_scanner_crawl.py` 的 link 循环与 mined 循环都只调
`_scan_reflected`),而 sync 对每个爬到的端点跑全套 page tasks(L3/L6 DOM +
高级页面层 + 请求层)。**Phase 214–216 已把这三条线补齐**(页层三件套 /
mined 端点 / L8 + JSONP),门:`test_phase214_crawl_page_layers.py`、
`test_phase215_crawl_mined_layers.py`、`test_phase216_crawl_request_layers.py`,
各自双引擎参数化并带变异对照。CORS 与 XS-Leaks 审计**刻意不接线**:两者在
层内按 ORIGIN 去重(`_cors_checked` / `_xsleak_audited`),seed 之后那一次
在结构上不可达,接上去只会是一记永远打不响的空枪。

**原改法形状的取舍记录**:没有抽"对一个端点跑全套"的共享入口,而是
在 async 侧逐层接线。原因与本条 2026-10-09 记的一样 —— 抽共享入口会把
async 爬取扫描的请求量按"端点数 × 页面层"放大,预算/超时/194 例 async
基线都要重测;逐层接线让每条线各自可归因、各自带门。
### 2.2 报告层性能

[report.py](file:///d:/qoder/xssentinel/xssentinel/core/report.py) **1428 行**,
六格式共存的字符串拼接在大 finding 数(>500)下会成为瓶颈。

**改法**:HTML 构建从 f-string 拼接改 `list.append` + `"".join`;
大报告 benchmark 化(`benchmark/` 加一例 1000-finding 合成负载)。

> **已测(2026-10-05,`benchmark/report_load.py`,结论:不做)**:1000 条
> 真实形状合成 finding(类型/上下文/严重度/证据级混合,proof/headless 全带),
> 八格式实测 —— html **0.053s**(1.37MB)、sarif 0.069s、burp 0.077s、json
> 0.044s、其余 <0.02s。HTML 比 2s 验收线快 **38 倍**,报告层不是瓶颈;
> f-string→join 重写属于没有测量支撑的优化,不做。基准脚本与结果 JSON
> 入库可复跑,报告层再演进时先重测。

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
2. **`'unsafe-hashes'` 从"检出"走到"利用"** —— **评估后关闭(2026-10-06,不可行)**:
   hash 授权要求脚本内容**精确匹配** `sha256-...` —— 攻击者经反射注入的脚本要被
   执行必须先求出该 hash 的原像(密码学不可行)。现实向量逐一排除:
   base-uri 劫持改写相对 src 后内容改变 → hash 失配被拦;移动/复制页面**自带**
   的已授权脚本不改内容、hash 仍有效 —— 但那需要先有另一个漏洞(DOM clobbering
   或 XSS),unsafe-hashes 不是短板。结论:对反射型输入面,unsafe-hashes 的
   "利用"没有可行路径,检出 + 修复建议(避免对可反射路径声明 unsafe-hashes)
   就是正确终点,不写投机 payload 逻辑。
3. **SSR hydration state 作为污点源**(`__NEXT_DATA__` / `window.__NUXT__` /
   `INITIAL_STATE`):Phase 189 评估后**决定不动**。理由:端点挖矿侧它已经被
   `js_miner.INLINE_SCRIPT_RE` 覆盖(JSON 里的 `"path": "…"` 走的正是同一个
   extractor),而把它加进 DOM 污点源列表会改变判定语义 —— 服务端渲染进 hydration
   blob 的数据是否攻击者可控,静态层面判不出来。要做就得按 176i/176j 的路子先给
   Chromium oracle 造出"可控/不可控"对照页测量,再决定接不接。竞品(nexa/ASTra)
   只把它当**提取源**,不当漏洞证据,这个尺度是对的。
4. ~~**净化器层没有独立靶场**~~ **靶场已落(Phase 225:`range6/`),门禁待 P1 修完
   转绿**:vendored DOMPurify 2.0.7(在 CVE-2020-26870 区间内,form/math/mglyph
   命名空间混淆 PoC 在真 Chromium 里**实测弹窗**)对 3.4.17(厂商当前版,同一
   PoC **实测被剥**),两页只差 script 标签指向的构建。构造效度沿用 range5
   (静态壳、参数只进客户端)。`tests/test_range6.py` 7 例全绿并含实时对。
   靶场同时量出三处 detector 缺陷并修掉两处(mXSS 提示版本盲区;TT 两条在
   sanitizer 介导流上的无证据 medium);第三条 P1 已由 Phase 265 收口。
   **门禁已转绿并挂进 CI**(sync/async TP1 FP0 TN1 FN0 ERR0),现状记在
   `range6/GATE_STATUS.md`。
5. ~~原有 1.2(async_scanner 拆分,现约 2960 行)~~ **已完成(Phase 191,纯移动 +
   逐字节/逐用例取证,见 1.2)**。剩余不变:1.3(sandbox 拆分)/ 2.1(双引擎
   判定去重)/ 2.3(range5 框架靶场)/ 1.0(第三方对照集,需换网络)。
   新增一项:**1.4 `_probe_param` 拆分**(683 行单方法)—— 它属于**改逻辑**,
   验收要配全量 194 例矩阵,不能和纯移动混做。
7. ~~**【最高优先级】DOM 层把"污点流入汇"当成了"执行",且证据是循环自证的
   (Phase 225 由 range6 量出,未修)**~~ **已修(Phase 265)**:
   `executed=True -> dom_dynamic/high（proof=sink 片段）；executed=False ->
   dom_sink_reachability/low（无 proof）`，类型/严重度只由
   `findings.dom_dynamic_finding` 决定；同时把 range6 实测的 form/math/mglyph
   mXSS carrier 加入 `_CARRIER_SHAPES`，正例重新拿到页面自弹窗的执行证据，
   safe 仍只落 low。**range6 双引擎 TP1 FP0 TN1 FN0 ERR0，已挂 CI**；
   全量双引擎已复跑（Phase 304，194 例）：**sync TP113/FP0/TN81/FN0/ERR0（858.36s）、
   async TP107/FP0/TN75/FN0/ERR0（12 SKIP，756.0s）**，见 README 当前基线；
   产物 `benchmark/results/xssmaze_tagaware_20261023_{sync,async}.json`。
   以下为 Phase 225 的历史分析：
   `dom_dynamic` 的
   `evidence_class=browser-executed` / `headless.outcome=fired` / high-high
   **全是常量**,不是量出来的。链路:① 探针注入的是**裸标记** `xssentinel_dom_<hex>`
   (污点标记,不是可执行载荷);② `_init_script` 的 `hit()` 只要标记出现在任何
   被挂钩的汇的入参里就记一击,**然后自己 `alert(MARKER)`**;③ `analyze()` 把每一击
   无差别变成 `dom_dynamic`/"…(marker executed)";④ `scanner_layers.py:197`
   (async 版 `async_scanner_layers.py:233`)硬编码 `{"confirmed": True,
   "outcome": "fired", …}`。
   **浏览器侧反证**(`dev/_r6_fp_probe.py`):把引擎自己记录的 replay 值送进去,
   两个孪生页上都只落为纯文本,**零弹窗、零活元素** —— "marker executed"是假的。
   设计意图就写在 `dom_engine.py` 的模块 docstring 里("fire alert(marker) so
   the dialog event is captured as hard proof" / "it means attacker input truly
   executed in a sink"),即**流入汇被等同于执行**。对未净化的 innerHTML 这条推断
   尚可辩护(innerHTML 会解析标记),但**净化器一旦在路径上就断了**:净化后污点照样
   进汇,载荷却会被剥。
   **为什么 benchmark 从没抓到**:`m_sanitizer_safe` 为了让 negative 不红,被迫绕开
   这个形状改用 textContent(注释里明说)。**canonical 正确用法(当前版 +
   sanitize→innerHTML)从来没有任何负面用例覆盖过**,range6 是第一个。
   **修法**:探针语料升级为**可执行载荷**,执行与否由页面自己弹的窗证明;去掉插桩里
   的 `alert(MARKER)`(循环自证,且往被测页面注入弹窗);`outcome` 只在真的观测到
   弹窗时才写 `fired`。**这是判定语义改动 ⇒ 四件套验收 + 基准重定基线**。

6. **被动代理 drain 循环只有字节上限、没有时间上限(Phase 224 记候选,未做)**:
   `passive_proxy.py:_relay` 对超限 body 的 drain 按
   `_BODY_LIMIT + 65536` 字节读,不设期限。声明一个大 Content-Length 却
   慢慢吐字节的客户端可以把一个 handler 线程钉住(ThreadingHTTPServer
   一线程一连接 ⇒ 慢客户端太多即线程耗尽,DoS 形状)。修法是给 drain 加
   截止时间(超时后仍发 413 + 关连接,走私安全语义不变)——但**这会改变
   对真实慢客户端(大文件上传)的行为**,属于独立决策,要单独量:
   基准里没有"慢速大 body"用例,先补用例再改。
   (同源背景:413 用例的 flake 是 13h 套件 ~20× 劣化下 2.1 MB 传输超 15s
   预算,Phase 224 按环境修了测试侧,产品侧这个候选仍开着。)
7. **async 的 polyglot 确认落点与 sync 分叉(L7 fallback vs L1 主循环),叠加评分
   类型收窄后记成 FN(Phase 308 门禁归因时量出,b1b5417 既有,未做)**:五个
   benchmark 阳性例(pos-markdown-01 / pos-formmine-01 / pos-jsmine-01 /
   aux-r-formecho01 / aux-r-jsecho01)sync 在主循环以 `reflected` 确认、async
   只由 L7 polyglot fallback 以 `polyglot_reflection` 确认,而 manifest 的
   `finding_types:["reflected"]` 不计后者 → async 全量记 FN5。原始报告里
   finding 在(`_invoke_scanner` 直调两棵树都可见),引擎并未沉默。动它 = 动
   async 的确认落点语义(把 polyglot 提进主循环候选,或扩评分类型表),要
   单独 Phase + 测量。另:p307_full_async.json 的 TP 路径是在未提交 WIP 树
   (早于 1580f8c 三分钟)上量的、加大预算(max_payloads 10/14/20)也造不
   出来,不能再当 b1b5417 的 async 基线引用。

---

## 4. 明确不做

| 事项 | 原因 |
|---|---|
| 清理 Mixin 的 `noqa: F401` 标记 | 运行时引用是 Mixin 架构的有意形态;现在的规矩是"必须带原因",不是"必须删掉" |
| 全量类型标注(mypy strict) | 111 模块体量下投入产出不匹配;保持 `test_no_undefined_names` 的 pyflakes 门控即可 |
| 重写 async 引擎为纯 asyncio 解析 | BS4/lxml 无 async API,`asyncio.to_thread` 是正确折中 |
| 引入重型 ORM/数据库 | range3 证明 SQLite 足够;API 持久化当前无规模压力 |
| 继续扩充自编 194 例基准 | sync 已 f1=1.000,边际信息为零;要新信息就去建 **1.0 的第三方对照集** |

---

### 3.8 ~~观测记录:async 每条响应的线程 CPU~~ 已结案(2026-10-06):诊断是错的,真凶是 L7 层网络泄漏

> 原记录(见 git 历史)把 ~55s/_probe_param 归因为"每响应的判定 CPU",
> 并计划建"线程内计时基线"。实测推翻:
>
> * **判定 CPU 是清白的**:包住 verify_semantic/sandbox/transform/analyze_all
>   等全部热点函数计时,210 次调用合计 **0.11s** —— 每响应判定 ~0.5ms,
>   与"门禁 async 单例 ~5s"从来对不上;
> * 成本不随 max_payloads/advanced_layers 变化(9 个请求也要 61.7s)
>   —— 按 _probe_param 调用次数计,不按请求;
> * faulthandler 周期转储线程栈:执行器线程**全程卡在
>   socket.getaddrinfo** —— 有人在桩 session 的测试里发**真实 HTTP 请求**;
> * 全局钩 `requests` 的 send 计数:6 次真实请求,全是 L7 层
>   (mutation `{{7*7}}` / dom_clobber / template / polyglot)的载荷探针,
>   经 `_get_sync_requester()` 的真实 Requester 发往测试用的假主机名,
>   每次不可解析域名在本机劣化 DNS 上超时 **7-11s**,6 x ~9s = 55s。

**根因**:async 的桩测试不密闭 —— 桩 session 挡住了 L1 主流,但 L7 层经
独立的 sync Requester 泄漏到真网络。生产路径下这些请求本来就合法
(层的载荷探针必须发),但测试里它们既慢又不确定。

**修复(Phase 200)**:`scan()` 创建真实 aiohttp 会话时置
`_sync_layers_online = True`;`_get_sync_requester()` 无此旗标即拒绝
("sync-layer transport is offline"),层的既有 try/except 将其如实降级为
"层不可用"。效果:14/12 预算的 _probe_param **62.7s → 0.44s**(142 倍),
196/197 系列的 HPP body 测试 55s+ → 0.66s。回归测试
`tests/test_phase200_hermeticity.py` 3 例(桩环境零真请求 + 守卫拒绝 +
生产路径置位)。遗留记账:sync 层 Requester 共享限速/代理/超时/cookie,
但**不经过** async 的 per-host throttle 与 189 的 egress jar —— 一次真实
不对称,待有需求再对齐。

### 3.9 ✅ 测试套件自身的可信度(Phase 206,两条新门 + 一次真因修复)

本文档此前所有条目都在问"**扫描器**测出来的是不是真的"。Phase 206 记的是同一
个问题问到**测试自己头上**:一个会静默失去覆盖的门禁,等于没有门禁。

**① 模块级 loopback 门禁(`tests/test_loopback_gate_placement.py`,5 例)**

`pytestmark = skipif(not SOCKETPAIR_OK, ...)` 挂在 Module 节点上,`skipif` 对
每个继承它的 item 求值,**无法按用例豁免**。主机劣化时整文件一起跳 —— 包括那些
一个网络请求都不发的用例。实测(`test_verify_carriers_live.py`,
`XSSENTINEL_FORCE_SOCKETPAIR=bad`):21 skipped 全跳,其中 6 条是守 paramless
兜底的纯断言,走桩、零网络。丢掉的正是 DOM 家族 finding 依赖的那条分支。

修法是**把门下沉到真正依赖 loopback 的用例**(模块级门根本豁免不了),已下沉
20 个文件;本条把它固化成门。门自带反证:注入一个模块级门必须让它变红 ——
一个抓不到已知违规的门,和"会跳过的门禁"是同一个毛病,只是高了一层。

**② loopback 靶场端口卫生(`tests/test_fixture_port_hygiene.py`,4 例)**

起因不是优化,是 `test_xs_leaks.py` 解除模块级门后**立刻转红**。根因不在
XS-Leaks 判定:源站确实发了 `Cross-Origin-Opener-Policy`,客户端没在跟它说话。

```
netstat -ano | findstr :9002
  TCP  127.0.0.1:9002  LISTENING     15668   <- python,2 小时前泄漏
  TCP  127.0.0.1:9002  ESTABLISHED           <- 我们自己的请求
```

靶场用 `for port in range(9002, 9014)` 挑端口,而 `http.server` 带
`allow_reuse_address = 1` —— **Windows 上 SO_REUSEADDR 允许第二个 socket 绑到
别人正在监听的端口**,所以 bind **成功**、`except OSError: continue` 永不触发、
`self.port` 报 9002,而连接落到泄漏进程手里。靶场永远不会发现自己连错了。

伤害量级才是重点:同文件的 `test_surface_found_when_opt_in` 本来就期望 1 条
finding,对着错误服务器**照样绿**——一个被占端口同时产出假绿和假红,两边都没
提端口。9 个靶场改为 `("127.0.0.1", 0)`:OS 保证独占,"被占"这个状态不存在,
不需要探测也不需要回退分支。

**没有"看起来安全"的固定端口豁免**。门的第一版给项目约定的 18xxx/19xxx 段
开了口子,理由是"段内碰撞概率低"—— 这正是 9002-9013 当初留下来时用的同一
个理由,而失败同样是静默的。最后一个带内 fixture(`test_escape_invariant_fuzz.py`
的 `PORT = 18878`)已一并改掉,规则现在只剩一句:**端口 0,否则不许绑**。
例外只有客户端 *connect* 到某个已知端口(如 `test_p27_api.py` 连 vuln_server
的 8899)—— 那不是 bind,门用"只查 `("127.0.0.1", <int>)` 元组第二项"天然区分。

**一条过期事实**:旧记"Windows 保留段 8810-9109,端口请用 18xxx/19xxx"——
`netsh` 现在列的是 1101-1200 / 5357 / 21879+ …,那段保留**已经不在了**。
避让规则仍是对的默认值,但**具体数字从来不是机制,SO_REUSEADDR 才是**;
ephemeral 绑定把机制本身去掉了。

**顺带收尾**:20 个文件下沉门禁后未删的 `SOCKETPAIR_OK` 导入留下 11 条 F401
(`ruff check` 红),已清;现全库 `All checks passed!`。

## 5. 执行顺序建议

```
已完成: 1.2 async 拆分(Phase 191)/ 1.0 外部效度对照(196b,60 例三工具同靶)
已完成: CSP 投递通道判定(header+meta、report-only 不再冒充保护)/ API 前端门对齐(196b)
已完成: 1.0 真实靶场复跑(Phase 219,Juice Shop 20.2.0 双臂各 1 条 browser-executed)
已完成: 2.3 range5(Phase 220,Lit)+ 2.1 parity 门扩到全 192 例(Phase 222,182 例 0 分歧)
仍未做: 1.0 商业工具 × 真实第三方靶对跑(现只有自建矩阵上的切片)
已完成: 1.4 _probe_param 拆分(Phase 211,787 → 171 行;当前 209 行)
下一轮: 1.0 的"商业工具 × 真实第三方靶"那一支
顺手:  3.x 随对应模块改动时一并处理
```

每一项的验收标准都已给出,**1.0 之外全部可离线验证**(测试命令或 ruff 退出码)。
1.0 是唯一依赖外部环境的项,也是唯一能回答"到底超没超越商业工具"的项
—— 它不该因为"麻烦"被无限期推后。
**Phase 222 的账要读准**:1.0 里"真实靶场"那一支(Juice Shop)已做并已出
结果,"商业工具在真实第三方靶上对跑"那一支仍未做 —— 两者不要混读成"1.0 做完了"。

**2026-10-03 环境复测(别把上面那段当成常驻事实)**:本机现在**完全出不了网**
—— 代理 `127.0.0.1:17054` 无监听(netstat 空),直连 `raw.githubusercontent.com`
curl exit 28。上面"GitHub API 是通的"那条反向实测写于 2026-10-02,已过期。
结论:1.0 的可执行性**逐日变化**,每次开工前先 `curl -m 10` 复测,不要引用旧条目。

---

## 6. Phase 207 新增:交付面(修复建议 + 报告类型表)的一致性审计

本文档此前所有条目都在问"**检测**对不对"(召回、误报、覆盖、性能)。
Phase 207 把同一个问题问到**交付面**:引擎判完之后,报告给用户的东西是否自洽。

方法:**三方交叉**,不靠猜 ——
① `report.py` 认不认(有 SARIF rule id 就叫认);
② 代码真的会不会发(`core/*.py` 里 `"type": "..."` 字典 **与** `type="..."`
关键字两种形态都要走,漏一种就漏一类);
③ 语料里有没有(`data/fix_advice.json`)。

结果量出两类真实缺口(均非崩溃、非误报,**所以此前没有任何测试会红**):

| 缺口 | 对象 | 用户可见症状 |
|---|---|---|
| 语料缺失 | `cors_misconfig` / `xs_leak_surface` / `upload_xss` / `stored_upload` / `stored_dom` / `source_map_exposed` / `bav` / `scenario` | 报告对 CORS 头回显、源码泄漏、上传文件名回显,统一建议"对输出做上下文编码" —— **方向错了** |
| 报告表缺项 | `stored_dom`(三表全缺)、`upload_xss` / `stored_upload`(缺 SARIF rule id)、`scenario`(三表全缺) | Burp/Nuclei 导出渲染 fallback slug `"stored dom (XSS)"` / `"scenario (XSS)"`;SARIF 塌成通用 `XSSENTINEL-XSS`,存储型浏览器确认的 finding 与反射型**不可区分** |

**落地**:语料 123 → 131 条;`report.py` 三张表补齐 5 个类型;
新门 `tests/test_fix_advice_coverage.py`(**12 例**)钉住**三条**不变量,含
**两条反证**(删语料 / 合成单表报告,门必须各自变红)与**一次真实注入验证**
(把 `scenario` 从三表移掉 ⇒ 门变红并指名 `['scenario']`),
外加**三条防空转断言**(表提取必须解出 ≥25 键、交集非空、`Finding(...)` 构造点 ≥8)。

**判据分两层是关键**:`"type": "..."` 也出现在 JSON schema(`"type": "object"`)
和 DOM 子结果里(`"type": "dom_sink"`,会被扫描器折叠成 `type: "dom"`),所以
第一层"发射集"刻意取宽,**只在与 report 的两张面向浏览器的表求交之后才下结论**
—— 子结果名天然出局,不需要豁免名单。
但**求交式判据看不见"根本不在任何表里"的类型**:`scenario` 就是这样漏掉的,
所以第二层用更严的判据(`Finding(...)` 调用的 `type=` 关键字)单独抓这类孤儿。
**豁免名单是上一轮刚从这个项目里删掉的东西**(见 3.9 的端口门:"18xxx 段碰撞概率低"
正是 9002 当初留下来的同一个理由)。

**教训(与 1.1 / 3.5 同类,但换了一层)**:前两次是"文档写完没回头核对代码",
这次是"四条各自维护的清单(`type_rule` / `type_name` / `_INTEROP_TYPE_NAME` /
`fix_advice.json`)之间没有门"。**清单分散在 N 处时,缺的从来不是细心,是把它们
钉在一起的测试。** 门落地当天就先抓到了自己的一处漏抓(提取器只走字典字面量,
`cors_misconfig` 因为走关键字形态而隐身)。

**下一步候选**(仍未做,按价值排):
1. ~~**2.1 parity 门扩容**到全 192 例~~ ✅ **已做(Phase 222)** —— 见 2.1.2;
2. **1.0 真独立靶场**(Juice Shop 全集 / 商业工具对跑):已做 Phase 219
        **FN 网的 FP 臂 + sink 维度(Phase 251)**:网此前单边(只猎 FN),
        验证器拒绝的组合从不扫描 ⇒ 转义盲 FP 家族结构性漏检;现已四态判定
        (covered/FN/neutralised/**FP 候选**)+ sink 第三维(198 组合)。首轮
        covered=122/FN 0/FP 候选 33,逐 finding 回验后 3 个真 FP(其中 2 个
        同一根因:SVG 语料的 `[\s\S]*?` 跨越 `</svg>`,已修)。**1 个未决**:
        UTF-7 `javascript:` URI 的 href reflected(高/高)与验证器无 charset
        分歧,动它即动严重度语义,留待带完整门的下一轮。
   (Juice Shop 20.2.0 双臂复跑),但"商业工具对跑"那一支仍未做;
3. ~~**2.3 range5**(Angular/Svelte/Lit,构造效度先行)~~ ✅ 已做(Phase 220,
   选型为 Lit:三个框架里只有它发布浏览器就绪的 ES module,无需编译步)。

#### 2.1.2 Phase 222:parity 门扩到全 192 例 —— 量到 2 处分歧,1 处是真 bug

方法先行:先写 `dev/_parity_matrix.py` 把双引擎跑遍 manifest(**182 例
可比**,另 10 例 manifest 里标了 `engines` 单边,既不记功也不记过),
再照测量结果建门。2.1 原文那句"难点不在写断言,而在先钉死可比的定义",
在这里的落点就是**可比集合本身**:

| # | case | 量到的形状 | 定性 |
|---|---|---|---|
| 1 | `pos-csp-02` | sync `csp_bypass medium None` / async `medium medium` | **真分歧(产品缺陷)** |
| 2 | `pos-pmmine-01` | sync `[]` / async `reflected high high` | **假分歧(量具缺陷)** |

**#1 是真 bug**:`scanner_layers._scan_csp` 直接 append `Finding` 而不走
`_record`,`confidence` 就没设,到报告层是 `null` —— 与 Phase 198
(polyglot)、Phase 209(`template_ssti_*`)**同一缺陷类**,那两次都补了,
`csp_bypass` 是漏网的最后一个。实测它是**全矩阵唯一**没有 confidence 的
finding 类型。已按 Phase 209 的同一理由补 `confidence="medium"`:
header 解析是确定的,但"这条策略可绕过"是从策略分析推出来的,
没有任何浏览器执行过被声称的路径。

**#2 是我自己造的**:隐藏参数挖掘在 sync 里住在 `scan_target()`
(`scanner.py:335`),在 async 里住在 `scan()` 生成器
(`async_scanner.py:578`)。我第一版量具用 `scan_endpoint()` 进 sync、
`scan()` 进 async —— **只在一侧挖矿**,于是凭空多出一条分歧。实测对照:

```
sync  scan_endpoint : []                      (53 req)
sync  scan_target   : [['reflected','high','high']]  (60 req)
async scan()        : [['reflected','high','high']]
```

改对入口后重跑全量:**182 例 0 分歧**(sync 586s / async 419s)。注意 sync
墙钟 355s → 586s,**正是因为两侧现在都挖矿了** —— 是量变准了,不是引擎变慢。

**门**:`tests/test_parity_full_matrix.py`。全量那一条 `XSSENTINEL_PARITY_FULL=1`
显式开启(15–20 分钟,不进日常 pytest);常驻的是三条秒级 shape 测试。
按 2.1 的规矩,AST 那条做了变异验证 —— **但它的第一版是假的**:
拿 `keyword.value` 和字符串比,而那是 `ast.Constant` 节点,于是**匹配到 0 个
调用**,在空列表上断言 `not offenders` 永远通过。摘掉 `confidence` 仍然是
绿的。现在解包 Constant 并且**断言至少匹配到一个调用** ——
匹配不到东西的门必须自己喊出来。

**教训(与 3.9/207 同族,又一层)**:"先写门再写实现"里最容易出的不是
假红,是**假绿**:一个语法上正确、逻辑上匹配不到任何东西的门,比没有门更
危险,因为它看起来在工作。本轮是变异验证救了它 —— 如果省掉那一步,
就会把这道假门当成"已覆盖 Phase 222"写进账上。
