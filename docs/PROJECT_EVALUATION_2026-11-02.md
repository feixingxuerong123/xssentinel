# XSSentinel 项目实战评估报告

| | |
|---|---|
| **评估日期** | 2026-11-02 |
| **评估对象** | xssentinel v1.3.0(main 分支,Phase 348 后工作树) |
| **评估性质** | 独立实战视角评审,**非项目官方文档** |
| **评估方法** | 静态审查:仓库文档、门禁体系、基准产物、核心源码;**未重新运行基准**,所有引用数字标注来源(见附录 B) |
| **口径声明** | 本报告遵守仓库自身证据纪律:每个数字标注出处与日期;"我方/官方文档声称"与"评估者当日实测"分开记账 |

---

## 0. 执行摘要

**一句话总评:这是一台"低误报的 XSS 专项重炮 + 反自欺工程体系"——检测维度与判定纪律在开源 XSS 工具里属第一梯队,但速度比 nuclei 慢一个量级、存储型自动检出偏弱、从未与商业工具对跑。它是纵深补充,不是一键全扫的替代品。**

三句话版本:

1. **检测能力**(官方第三方 XSSMaze 靶 F1 0.965、FP=0,vs dalfox 0.853 / nuclei 0.836):DOM 动态执行确认、盲打 OOB 收网、CSP nonce 利用链是开源独一档,且误报控制直接决定"敢不敢跑完就交差"。
2. **实战摩擦**:速度(慢一个量级)、存储型(第三方靶 2/10)、爬虫轻量(深度 2)、双引擎能力不对齐——决定了它宜做"广度快筛之后的深度复核器",而非流水线第一环。
3. **工程质量**(13.3 万行、源测比≈1:1、变异对照守卫、文档数字与代码一致性门禁):反自欺体系是本项目最深的护城河——你看到的每个基线数字都可复现。

---

## 1. 评估维度速览

| 维度 | 评分 | 一句话 |
|---|---|---|
| 检测深度/维度 | 4.5 / 5 | 52 个注册检测层;DOM 动态确认、盲打收网、CSP 利用链开源少有对手 |
| 低误报可信度 | 4.5 / 5 | 官方第三方靶 FP=0;证据分级(浏览器已执行/OOB/语义确认)诚实 |
| 速度/规模化 | 2.5 / 5 | 比 nuclei 慢一个量级;大攻击面依赖预算档位与分批 |
| 工作流集成 | 4 / 5 | 入口面极全(HAR/OpenAPI/sitemap/wayback/MCP/SARIF);157 个参数学习曲线陡 |
| 存储型 | 3 / 5 | 自动发现弱,需人工配对注入/展示端点或 DSL/被动代理补 |
| 工程可信度 | 5 / 5 | 反自欺基础设施在开源安全工具里几乎无同类 |
| 外部效度 | 3 / 5 | 仅 XSSMaze + Juice Shop;无商业工具对跑、无真实赏金项目样本 |

---

## 2. 检测能力:实战中最值钱的部分

### 2.1 检测面

`xssentinel/core/coverage.py:42` 的 `LAYERS` 注册表实测 **52 个检测层**,覆盖九个层级:

- **L1–L2 基础**:反射探测、CSP 预算门控、预编码管道(base64/JWT/JSON 容器同构注入)、反射画像、参数位置变换、HPP;
- **L3–L6 DOM/存储/盲打**:静态污点、AST 数据流(esprima,可选 extra)、真浏览器插桩确认(Playwright sink 钩子 + token 溯源)、存储两步、二阶观察、OOB 收网(self / interactsh);
- **L7–L9 高级**:mXSS、DOM clobbering、CSP nonce/gadget、dangling markup、sanitizer bypass(DOMPurify 版本线,Phase 189 现代化)、cookie tossing、GraphQL、upload filename、参数/JS 端点/表单挖矿、声明式场景 DSL。

完整清单见附录 A。

### 2.2 实战中拉开差距的四项

| 能力 | 实战价值 | 说明 |
|---|---|---|
| **DOM 动态执行确认** | 极高 | 不是静态猜,而是真实浏览器里 sink 插桩 + 唯一 token 溯源——**页面自己执行了载体才报 high `dom_dynamic`**;只到 sink 未执行记 low 投递线索。能区分"净化器用对了"与"没净化"(DOMPurify 2.0.7 真执行 / 3.4.17 静默双向验证)。多数工具(含 dalfox)不做这个区分 |
| **语义确认降误报** | 极高 | token 必须落在真实可执行汇聚点;`html.escape` 页面零误报。XSSMaze 官方靶 FP=0(dalfox/nuclei 各 4 个 CSP 页误报)。实战中误报 = 人时浪费,这决定你敢不敢把它跑完直接交差 |
| **盲打 OOB 收网** | 高 | `--oob interactsh` 收到 beacon 才确认,"撒网必收网",可直接报 SRC;`--oob self` 本地监听离线可测 |
| **CSP nonce 泄露利用链** | 高 | 自动读取页内泄露 nonce 构造同 nonce script;验证器核对 nonce 与响应头一致性防误报。手工渗透里费眼力的活,自动化了 |

### 2.3 外部效度数据(均为官方文档记载口径,本报告未复跑)

**官方 XSSMaze v0.3.0(2026-10-30,Phase 342,官方 runner 同 scorer):**

| 工具 | TP / FN / FP | P / R / F1 | 墙钟 |
|---|---|---|---|
| **XSSentinel** | 944 / 69 / **0** | 1.000 / 0.932 / **0.965** | 5741s |
| dalfox v2.13.0(Go 冻结分支) | 757 / 256 / 4 | — / — / 0.853 | 4072s |
| nuclei v3.9.0 | 731 / 282 / 4 | — / — / 0.836 | **406s** |

分类差距在 **dom(我方 170/174 vs dalfox 75、nuclei 50)** 与 stored(2/10 vs 均 0/10)——最擅长的是现代前端 DOM 型,恰是实战中 SRC 最易中、也最需要浏览器确认的一类。

**同靶快照(phase196,自编矩阵 60 例切片,2026-10-04)**:XSSentinel F1 0.986 / 346s,dalfox 0.825 / 1173s,nuclei 0.839 / 49s。速度劣势在该表更刺眼。

**真实第三方应用**:OWASP Juice Shop 20.2.0 一条命令 `-u <origin> -c --headless` 报出 `dom_dynamic` high(对应上游 `localXssChallenge`),双引擎各命中一个不同真实 sink,且同轮修掉一个 critical 级假阳性(SSTI 行号误判,Phase 209)。

**语料覆盖对照**:PortSwigger XSS cheat sheet(822 向量)「无需用户交互」主指标组三维(事件/标签/协议)**全部 100%**(2026-11-01 复跑)。

**必须打的折扣**(README 自己声明,此处照录):
- XSSMaze 对跑中我方记分卡复用 p341(两树检测面零提交差);dalfox 为 Go 冻结分支 v2.13.0,非现行 Rust v3,其 chromedp headless 层被 `--skip-headless`;
- phase196 靶为自编,"别人出的题只到位一半";
- PortSwigger 数字是字符串级覆盖,不等于端到端检出;
- **Burp Pro / Acunetix / Netsparker 从未对跑**(OPTIMIZATION.md 列为需外部条件)。

---

## 3. 实战工作流可用性

入口面几乎覆盖每种渗透工作流:

- **侦察管道直连**:`--batch-stdin`(httpx/gau 流式)、`--batch`、`--har`、`--openapi`、`--sitemap`、`--wayback`(CDX API)、`--raw-request`(Burp copy-as-raw)、`--gql`;
- **认证**:表单登录(含 CSRF 字段/成功 marker)、basic、header、JSON token path、会话丢失检测(`--session-check` + `--on-session-loss abort`,死会话不装绿)、`--auth-relogin-on-loss`;
- **节奏与规模**:`--scan-policy {quick,normal,deep}` 预算档、`--rate-limit`、`--checkpoint/--resume` 断点续扫、`--scope` 限域、`--skip-param`;
- **交付物**:每个 finding 自动产出 **curl + payload URL + 自包含 HTML PoC**;8 种报告格式(html/json/csv/sarif/junit/markdown/burp/nuclei),SARIF 直接进 GitHub code scanning / 缺陷平台;报告按**证据类**分级(浏览器已执行 / OOB / 浏览器未复现 / 未用浏览器 / 语义确认),`dom_dynamic` 未观测执行时明确标"投递证据"不按已执行读;
- **Agent/平台接面**:MCP 七工具(发现→画像→挖参→CSP→扫描→verify 重放→LLM propose 但 token oracle 裁决)、REST API(`--serve`)、远程 MCP(Streamable HTTP)、桌面控制台;参数契约"未知键=响亮报错,永不静默丢弃"。

**一个易被忽视的实战安全设计**(Phase 189):跨源 302 时剥离 `Authorization`/`Cookie`/自定义头,实测默认模式曾把 40 余个探针送到第三方源、开启防护后为 0。解决的是**扫描器自身变成凭据外泄载体**的风险。

**不足**:157 个 CLI 参数的复杂度是真的(子命令 `scan/serve/selftest/mcp` 拆分后 `--help` 已收敛);新手应严格走 `docs/QUICKSTART.md`,不要从 README 能力清单上手。

---

## 4. 实战短板(按影响排序)

1. **速度是硬伤**。nuclei 快一个量级(XSSMaze 406s vs 5741s;phase196 49s vs 346s)。内部 194 用例本地 sync 约 12 分钟、async 约 25 分钟(README 基准工具链节)。对单目标精扫可接受;对数千 URL 的攻击面,预算制(默认 12 transforms / 10 payloads)成为瓶颈。`--jobs N` 并行 runner(A/B 3.75×)目前只加速**测试**,不加速**扫描**。
2. **存储型自动检出弱**。XSSMaze stored 组 2/10;自有靶上强是因为操作者手动给了 `--stored-inject/--stored-view` 配对。被动代理 + 二阶观察 + `--scenarios` DSL 能补,但"自动发现写入→展示流"仍是最弱一环——而存储型在 SRC 分值往往最高。
3. **爬虫轻量**(BFS 默认深度 2)。复杂 SPA 依赖 `--headless` 或人工喂入口;鉴权流、CSRF 轮转页面的自动遍历不能指望替代 Burp。
4. **双引擎能力不对齐**。`--stop-at-cross-origin` 仅 sync(aiohttp 跳转循环无法中途终止,CLI 显式警告);CORS/XS-Leaks 在 async 爬取路径刻意未接线;架构文档记录的 shim 缺口中 `skip_params` 曾把 `--skip-param` 静默降级。用 `--async` 批量时要知道自己在用一条"略瘦"的流水线。
5. **缺真实世界样本**。全部外部数据在 XSSMaze/自编靶/Juice Shop 上;没有任何来自真实赏金项目的检出/误报统计。F1 0.965 不能直接外推到你的目标。

---

## 5. 工程质量:真正的差异化

体量:源码 133 文件 58,936 行 / 测试 265 文件 60,685 行,≈1:1(2026-11-01 复测,AGENTS.md);258/258 测试文件绿(exit 0,4554s,skip 75 例/10 文件两数并报,Phase 346);CI 6 job。

但比数字更难得的是**度量文化**:

- 守卫做**变异对照**(baseline/mutated/restored 三遍,mutated 红 + restored 绿才算数);
- 引用数字必须出自自己的运行;"绿"必须连 skip 数一起报;**`passed==0 && failed==0` 单列 verdict,零永远不是通过**;
- 文档数字与代码一致性有门禁钉住(`tests/test_quick_gate_slice.py`、`tests/test_doc_code_counts.py`);
- `docs/OPTIMIZATION.md` 有明确"不做清单",每项有测量依据(如 f-string→join 重写实测 1000 findings 仅 0.053s,非瓶颈,放弃);
- README 每个对跑结论自带"这个数字不能说明什么"。

架构:双流水线 Mixin 化 + AST 契约测试钉住 Mixin 隐式链接、场景 DSL(Nuclei 风格声明式多步)、数据化修复建议(132 条语料)。扩展成本低:加 payload 改 JSON、加变形注册 REGISTRY、加场景写 JSON。

对一个安全工具,这直接转化为实战信任度:**文档里的每个基线数字都可复现,且"检测面"与"检出率"两条证据链分开陈述**。

---

## 6. 与同类工具的实战定位

| | XSSentinel | dalfox | nuclei | Burp Pro |
|---|---|---|---|---|
| 定位 | XSS 专项纵深 | XSS 专项 | 泛模板引擎 | 全栈商业平台 |
| 同靶 F1(XSSMaze) | **0.965** | 0.853 | 0.836 | 未对跑 |
| 速度 | 慢一个量级 | 中 | **最快** | — |
| DOM 浏览器确认 | 插桩+溯源 | chromedp 层 | 模板级 | 有 |
| 盲打 OOB 收网 | 有(interactsh/self) | 有限 | 模板级 | 有 |
| 存储型 | 需配对/DSL | 弱 | 弱 | 强 |
| 生态/CI 接入 | SARIF+MCP+API | CLI/pipe | 模板生态最广 | 成熟 |

**实战结论**:它是 XSS 的"专家会诊",不是"全科筛查"。合理分工是 nuclei/dalfox 广度快筛 → XSSentinel `-c --headless -f sarif` 深度复核 DOM/盲打/CSP → PoC 直进缺陷单。

---

## 7. 实战使用建议

1. **分工**:广度交给 nuclei(速度),深度交给 XSSentinel(精度与证据分级);
2. **盲打必开** `--oob interactsh`(真实场景);被动代理挂浏览器日常挂机收存储流(`--passive --mitm-ca`);
3. **CI/平台侧**:SARIF 出口 + `--mcp` 让 Agent 编排"发现→验证→提议 payload"循环(模型提议永远经 token oracle 裁决,不是模型说了算);
4. **高价值目标**:`--scan-policy deep` + 手动喂认证态;存储型场景用 `--scenarios` 显式声明写入→展示流;
5. **记住折扣**:引用本工具任何数字时,连同其口径限定(自编靶/冻结分支/未对跑商业工具)一起引用——这是本仓库自己的规矩。

## 8. 提升路线(如果只做三件事)

1. **攻速度**:扫描侧并行预算分片(现在是墙钟短板,与测试 runner 的 `--jobs` 是两回事);
2. **攻 stored 自动发现**:从"需人工配对"进化为"自动发现写入→展示对"(把最强单项补成无死角);
3. **一次真实 SRC 项目实证**:10 份真实报告的检出/误报统计——这是当前证据链上唯一缺失的一环,README 的诚实声明已经自己承认了。

---

## 9. 落地进度(2026-11-02 起,边做边更新)

§8 第 ①② 项已开工。约定:每个 Phase 独立提交;本表是唯一进度台账,引用数字均为当日实跑。

| Phase | 内容 | 状态 | 守卫与证据 |
|---|---|---|---|
| 349 | sync batch 多目标并行 `--batch-workers N`(默认 1 逐字节不变) | **已完成(2026-11-02)** | `tests/test_batch_workers.py` 8 例全绿(解析契约含显式 0 不被 `or 1` 吞掉、双模式 verdict 一致、**并行驱动真实生效 banner 断言**、失败隔离 rc=3 + checkpoint 标记);既有 test_batch_input/test_p25/test_completeness_gate_robust 91 例全绿;ruff 通过。**A/B 实测**(本机,3 目标本地靶 30ms/req,预算 4/2):顺序 11.98s/12.13s → workers=1 12.01s(报告内容与 baseline **逐字节一致**,仅时间戳/随机 token 归一)→ workers=3 **5.00s(2.4×)**,verdict 一致。全量口径待 Phase 354 全门禁后引用 |
| 349 附记 | 顺带发现(未修,既有语义非本次回归):批量报告顶层 `requests_attempted` 一直是"共享 tally 在该目标报告写出时刻的**累计值**"(顺序实测 68→136→213 递增);并行下表现为多目标读到接近最终值(总和不变)。属报告语义怪癖,已记 OPTIMIZATION 候选 | 记录 | A/B 数据同上 |
| 350 | threads>1 并行分支 checkpoint/进度回调修复(探索中发现的真 bug) | 待做 | — |
| 351 | async batch 多目标并发(有界 gather) | 待做 | — |
| 352 | second_order 去重保 viewer 证据 | 待做 | — |
| 353 | StoredWatch 主动模式存储自动发现(核心;默认开,`--no-stored-watch` 可关) | 待做 | — |
| 354 | 基准复跑 + 文档四面 + 本文档 §1/§4/§8 对应条目改注 | 待做 | — |


---

## 附录 A:已注册检测层清单(52 个,`xssentinel/core/coverage.py:42`,2026-11-02 实测)

<details>
<summary>展开全量清单</summary>

- **L1**:`L1_reflected`、`L1_csp_gate`、`L1_pre_encoded`、`L1_reflection_profile`
- **L2**:`L2_waf_evade`、`L2_hpp`、`L2_position_shift`
- **L3**:`L3_dom_static`
- **L4**:`L4_stored`、`L4_stored_dom`、`L4_second_order`
- **L5**:`L5_blind_oob`
- **L6**:`L6_dom_dynamic`
- **L7**:`L7_mutation`、`L7_dom_clobber`、`L7_template`、`L7_polyglot`、`L7_jsonp`、`L7_csp`、`L7_time_based`、`L7_csp_nonce`、`L7_csp_gadget`、`L7_css_injection`、`L7_dangling_markup`、`L7_import_map`、`L7_sanitizer_bypass`、`L7_sri_bypass`、`L7_svg_xss`、`L7_cors`、`L7_nonce_bypass`、`L7_xsleak`
- **L8**:`L8_postmessage`、`L8_prototype`、`L8_service_worker`、`L8_web_worker`、`L8_open_redirect`、`L8_framework`、`L8_header`、`L8_path`、`L8_cookie`、`L8_error_page`、`L8_markdown`、`L8_cookie_tossing`、`L8_graphql`、`L8_trusted_types`、`L8_websocket`、`L8_request`
- **L9**:`L9_param_miner`、`L9_js_miner`、`L9_form_miner`、`L9_scenario`、`L9_upload_filename`

</details>

语料规模(评估期间清点):`payloads.json` 1198 条(40 上下文)+ 36 polyglots;`svg_xss.json` 60 条;WAF 指纹 56 个(`core/waf.py`);绕过变形 28 家族(`core/transform.py` REGISTRY);隐藏参数词表 313 条;修复建议语料 132 条(`data/fix_advice.json`)。

## 附录 B:证据引用对照表

| 本报告数字 | 来源 | 日期 | 评估者是否复跑 |
|---|---|---|---|
| XSSMaze 944/69/0,F1 0.965,5741s;dalfox/nuclei 对照 | README「外部效度」节,产物 `benchmark/results/phase342_xssmaze/` | 2026-10-30 | 否(引用官方产物) |
| 内部 194 例 sync 113/0/81/0、async 107/0/75/0+12 SKIP | README「当前基线」,产物 `xssmaze_tagaware_20261023_*.json` | Phase 304 | 否 |
| phase196 三工具 60 例 | README,产物 `phase196_cross_tool.json` | 2026-10-04 | 否 |
| PortSwigger no_interaction 组 100%×3 | README,产物 `portswigger_corpus_coverage.json` | 2026-11-01 | 否 |
| Juice Shop 单命令命中 | README Phase 209 段 | — | 否 |
| 52 个检测层 / 133 文件 58,936 行 | **评估者当日实测**(`coverage.py` / 文件遍历,与 AGENTS.md 2026-11-01 记载一致) | 2026-11-02 | **是** |
| 语料规模(1198/36/56/28/313/132) | 评估期间源码清点 | 2026-11-02 | 是(清点非运行) |
| 258/258 测试绿、skip 75/10、4554s | AGENTS.md Phase 346 | 2026-11-01 | 否 |
| 凭据外泄 40+→0 实测对照 | README Phase 189 段 | — | 否 |
| stored 2/10、dom 170/174 vs 75/50 | Phase 342 逐例数据(agent 审阅 `benchmark/results/phase342_xssmaze/`) | 2026-10-30 | 否 |
| 本机扫描耗时口径(sync 12min / async 25min) | README 基准工具链节 | — | 否 |

## 附录 C:方法论与局限

- 本报告为**静态审查**:未运行扫描器、未复跑基准、未做任何目标探测;所有"实测"仅指对仓库文件/源码的当日清点与核对。
- 引用的基准数字均为**官方文档记载**,其口径限定(靶场来源、竞品版本、skip 数)以原文为准,本报告已尽量逐条转述,不构成二次验证。
- 评分为评估者基于上述证据与开源安全工具领域通识给出的**主观判断**,供决策参考,不构成项目质量认证。
- 与商业工具的对跑缺失、真实赏金样本缺失,既是本报告的局限,也是项目自身承认的局限(见 `docs/OPTIMIZATION.md` §7)。

---

*本报告由独立评审生成于 2026-11-02;如项目后续版本变化,数字以仓库内带日期的基准产物为准。*
