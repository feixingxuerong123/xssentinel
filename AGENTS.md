# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

定位:在开源工具中做到**检测维度最全、架构最干净、最易扩展**(见 README「定位与诚实声明」)。

**文档地图**(2026-10-31 起本文件只保留规则与状态,过程日志全部归档):

| 要找什么 | 去哪 |
|---|---|
| 逐 Phase 过程日志(176f–345,每项改动的归因、门禁证据、自我纠正) | `docs/archive/AGENTS_phase_log_to_20261031.md` |
| README 历史 Phase 叙事(基线演化、缺陷家族、自我纠正;2026-11-01 蒸馏出库) | `docs/archive/README_phase_log_to_20261101.md` |
| Phase 350–357 轮次报告(345 之后的逐轮实测数字与归因) | `benchmark/results/round2..round5_*_20261103.md`、`zap_unavailable_20261103.md`;Phase 357 证据见 `benchmark/results/benchmark_full_{sync,async}_20261104.json`、`bwapp_matrix_pre_fix_20261103.md` 与提交 `f80af43` |
| Phase 364–371 轮次报告(2026-11-07~08) | `benchmark/results/*_20261107.md`、`*_20261108.md`;外部效度证据分级与不可比项见 `external_validity_20261108.md` |
| Phase 400–407 轮次记录(2026-11-17~21)与 2.2.1 交付收口 | `docs/OPTIMIZATION.md` §8.31–8.39、CHANGELOG `[2.2.0]`/`[2.2.1]`、`benchmark/results/*2026111{7,8,9}*`/`*2026112{0,1}*`、`docs/PHASE400_HANDOFF_20261118.md` |
| 开发约定 / 回归靶场 / 架构约定 | `CONTRIBUTING.md` |
| 门禁体系如何运作 / Mixin 隐式契约 | `docs/ARCHITECTURE.md` |
| 优化 backlog(含明确不做清单) | `docs/OPTIMIZATION.md` |
| 安装、使用、能力清单 | `README.md` |
| 新维护者上手路径(第一周怎么跑) | `docs/ONBOARDING.md` |

## 规则约定

### 架构硬规则

- scanner.py 已 Mixin 拆分(2026-11-01 实测:核心 2246 行 + layers 936 + crawl 483 + stored 982 + findings 377):新增能力进对应 Mixin,不堆回主文件。**行数上限由 `tests/test_architecture_scale.py` 钉住**(核心 2400 / layers 1050 / crawl 550 / stored 1100 / findings 450);超限只有两条路——拆,或显式抬预算并在提交信息里写明理由。上一版(2026-10-05)的实测数字是 1869/769/406/579/216,即四周内核心涨了 20%、stored 涨了 70% 而无人报警,这就是把数字改成上限的理由:被测量的规则才是规则
- async_scanner.py 已同样 Mixin 化(2026-11-01 实测:核心 1434 行 + layers 2148 + crawl 588 + verify 119 + common 490,Phase 191):新增 async 能力进对应 Mixin,不堆回主文件;**搬代码与改逻辑绝不混在同一轮**。上限同由 `tests/test_architecture_scale.py` 钉住(1600 / 2350 / 650 / 145 / 520)
- fix_advice.py 数据化(2026-10-05 实测:127 行引擎 + JSON 语料):改建议优先改语料
- 多步检测优先写场景 DSL,而非过程式代码

### 工程纪律(从 300+ 个 Phase 的实测教训蒸馏;完整论证见归档对应段落)

**测量先行**

- 让判定有测量支撑,而不是让基准更好看;**没量过的东西不进门禁,量过是不需要的更不该进代码**。
- 引用门禁数字必须来自自己的运行;「最新的目录」不是「我的目录」,证据先确认归属;证据不存在时删掉佐证,不找现成的顶上(Phase 201 续十二)。
- 「绿」和「跑过」是两个词:引用门禁结果必须同时给出跳过数(`env_gated_tests`);整文件 skip 的门禁什么都不曾贡献(Phase 201 续十三)。
- 零永远不是通过:`passed==0 and failed==0` 必须单列成独立 verdict,不能落进 `failed==0` 的分支;没有摘要行 ≠ 没有失败(归档「五条新规则」)。

**测试与守卫**

- 变异对照:先断言文本存在再变异(找不到就 ABORT,绝不「跑一遍看看」),跑 baseline/mutated/restored 三遍,只有 mutated 红且 restored 绿才算数(Phase 201 续三)。
- 守卫空转的五种失效形状:测了表示没测被测物 / 对照集用并集 / 只测单向漂移 / 凭信念列名单 / 集合本身可增删无告警(Phase 201 续四~七)。
- 探针必须调**真实入口**,不是听起来合理的那个;替身保真度要量——替身能响应真实代码不可能发出的调用,是最危险的假绿(Phase 201 续二)。
- 清单分散在 N 处时,缺的不是细心,是把它们钉在一起的测试;判据收窄到「两边都认」,不引入豁免名单;反证要用真的检测函数跑(Phase 207「三条可复用规则」)。

**文档刻度**

- 文档里的数字必须与代码一致:`tests/test_quick_gate_slice.py` 钉住切片/矩阵数字,新增数字声明时同步加钉;历史数字允许留在带日期的记录里,不允许以现在时出现(Phase 190)。
- 全量分批门的运行时口径(文件数 / 两组数 / skip 数)另由 `tests/test_doc_gate_parity.py` 钉中英 README、CHANGELOG 与 AGENTS.md 同源:引用门禁结果必须带跳过数,旧口径不许以现在时回潮(2026-11-04 文档一致性收尾,处置记录见 `docs/OPTIMIZATION.md` §7 item 4)。带日期的历史记录不受该闸管辖,禁止为过闸去改它们。

**层注册**

- 新增检测层必须**同时**注册 `coverage.LAYERS` 与 `layer_coverage` 矩阵(Phase 187/192 两次被门禁抓到的同一课)。

## 当前状态(2026-11-23)

- **[2.2.1] / 交付收口轮(2026-11-23)**:把悬在未提交树上的 Phase 400–407
  (11-17~21)按依赖闭包拆分入库,定版 **patch 2.2.1**(全部为缺陷修复/测量
  工具,无产品契约破坏;404 竞品 runner 属 benchmark 工具非产品能力)。
  收口动作:CHANGELOG 补 **400-headless** 条目(此前缺失)、390–398 明细
  归档回 `[2.2.0]`(该节早已声明随版发布却留在 Unreleased);OPTIMIZATION
  两个 §8.31/§8.32 重号顺移为 §8.33–8.38 并同步全部交叉引用;
  **Phase 400 编号撞车**(GET 缓存写条件 `4339e8e` 与 headless 认证重放
  两条独立流)如实记账、不追溯改名,以标题后缀与文件/提交为准。
  凭据处置:`benchmark/results/llm_state.json`(运行期状态)与
  `llm_local_glm53_20261119.json`(含真实 API key)进 .gitignore;
  DVWA AI 报告证据中的 key 为产品自身脱敏形式(`sk-369***f3cb`)可入库,
  16 份报告与脚本/交接文档逐一 grep 确认无完整密钥/PHPSESSID。
  v2.2.0 补 tag(399 终树 `fddff54`),v2.2.1 打终树。**门禁数字见
  CHANGELOG [2.2.1] 验收节与 OPTIMIZATION §8.39**。
- **Phase 407(2026-11-21,async 无反射 L1 穷举收敛)**:全量 async 20564
  请求 vs sync 7915(2.6×)定位到无反射参数 fall-through 满预算 ladder。
  修法严格解耦:独立信号 `marker_absent` 只把 `_build_probe_candidates`
  的 cand_budget 14→3,**绝不进 `marker_escaped` 总开关**(第一次折叠尝试
  致反射正例 pos-elem-01/neg-filter-01 FN,单 case repro 2 分钟抓出、
  完整回滚);另补 sync 的 `find_prefix_encoded_marker` 零请求保底。
  无反射 case 245→~96 请求、检出不变,反射正例请求逐位不变。守卫 5 +
  变异 3/3。**债**:async 分批全量门只跑 71/194(loopback 劣化,原 runner
  重试放大成 19h hang),交付轮补跑;性能墙钟劣化期不可比不宣称提速。§8.38。
- **Phase 405(2026-11-20,onload 资源加载失败高估修复)**:真 Chromium 148
  探针证明 onload 只在资源真正加载成功时触发(无效 scheme/相对 404/空 src
  全走 onerror)。sandbox 仅对资源元素 onload 的 src 带**显式不可加载
  scheme** 降 inert;onerror/相对/绝对/data/blob/iframe 无 src/svg onload
  一律不动。守卫 15 + 变异 3/3 + 全量 194 双引擎质量门绿(async 性能
  860.9s/840s 超 2.5% 如实记——请求量 2.6× 是本机 async 吞吐边界非回归)。
  竞品 M1 原 2 例 overstated 复测归零。§8.37。
- **Phase 404(2026-11-20,竞品测试文件三类接入)**:6 家竞品源码按资产形态
  分流——payload 库 1516 条带来源实测(M1 1884 页 missed 0 / overstated 2,
  后者由 405 修)、官方靶用例记录不打分、单元测试只做契约对照不转嫁分数。
  E2E 4 臂:baseline/XSStrike 7/7、dalfox/XSSer 6/7(竞品载荷集覆盖差异,
  非我方检测回归)。事实表非分数,不与 194/XSSMaze 并列;runner
  `benchmark/run_competitor_corpus.py` + 守卫入库。§8.36。
- **Phase 403(2026-11-19,证据分级修真)**:`llm_propose` 改走
  `findings._grade_evidence` 唯一权威——真浏览器弹窗确认不再被标最弱的
  `model-only`。async cookie「不等价」定谳为 **aiohttp/requests 会话生命
  周期架构差异**(async 每请求新建 session,jar 本就不跨请求),不是可修
  adapter 漂移,不改;要改须先拿认证靶场 sync/async headless A/B 量出真
  漏报。§8.34。
- **Phase 402(2026-11-19,三项零争议收口)**:MCP `_abs_http_url` scheme
  白名单(`file://`/`gopher://` 不再进 `page.goto`)、截图只在 confirmed
  采集(反证路径不再白吞 2MB 含会话数据的图)、DVWA PHPSESSID 改写到系统
  临时目录 + .gitignore 兜底 + 不回显。判定层零改动。§8.33。
- **Phase 401(2026-11-18,onstart 悬案定谳)**:Phase 391「证据冲突」定谳为
  **假冲突**——XSSMaze level5 真页面是纯静态 `<div #{query}>` 无脚本无派发
  (拿真源码核实),Phase 362 那条 marquee onstart 是 `browser-unavailable`
  从不是浏览器执行。有效对照(load+hover)复测:三个 onstart 形状浏览器
  全不执行而 verifier 全确认。**定谳≠修复**:扩 `INERT_HANDLER_PAIRS`
  覆盖其余 11 形状属判定语义变更,**仍开放**,须独立轮 + 对照矩阵 + 全量门。§8.32。
- **Phase 400-headless(2026-11-18,认证重放注入会话 Cookie)**:
  `verify_headless` 无 cookies 参数 + 调用方只传 headers( Cookie 在
  `session.cookies` 不在 headers)⇒ 浏览器重放撞登录墙、诚实 high 被误判
  `browser-refuted`。修:`session_cookies()` 唯一收口、`_browser_cookie_entries`
  合并显式 cookies 与 Cookie header(拆 `;`、按 name 去重)、Cookie 剔除后
  Authorization 存活、POST `data=`→`form=`;sync 3 点 / async / MCP
  verify+propose / llm_propose 全链透传。DVWA high 真靶
  browser-refuted→**browser-executed**;全量 194 双引擎绿(11-18)。
  交接 `docs/PHASE400_HANDOFF_20261118.md`。
- **Phase 400-cache(2026-11-17,`4339e8e` 已推送)**:`Requester.get()`
  缓存**写**条件漏 `not headers`(读条件有)⇒ canary 被弹回登录页时把
  LOGIN 写进裸 URL LRU,之后所有默认裸 GET 静默读脏页。修源头一处保护
  所有读者(396 读者侧修复保留作纵深);仅 sync(async 无此 LRU)。§8.31。
- **开放项(2026-11-23)**:① onstart 其余 11 形状判定修复(已量未修,
  独立轮);② 默认模式是否开浏览器自证(handoff §6 P1,**需拍板**);
  ③ `trusted_types_no_policy` 算不算 finding(§8.35 三选项,**需拍板**,
  改报告契约连带 benchmark 分母);④ async cookie 架构差异(需先 A/B 测量);
  ⑤ PyPI Trusted Publisher、wsl.exe 解封(XSSMaze 复测前提)——归属者外部待办。
- **[2.2.0] / Phase 399(2026-11-17,REST `dom_engine` 值域校验——BREAKING)**:
  闭合 §8.28/§8.29 连续两轮记下的「REST 对 `dom_engine` 无值域校验,
  `bogus` 202 直通并静默构造真 Chromium」(与 397「off 被忽略」同族)。
  **先量再修**:同一量具 12 臂调真实 `_handle_create_scan`,修复前基线
  沿用 Phase 398 带日期快照(本轮不伪造基线)。修法:值域从 MCP
  `_TOOL_SCAN_SCHEMA` enum 读取(lazy import 避循环,**不在 REST 手抄
  第五份**),大小写不敏感归一复刻 MCP `_check_type`,非法值 400
  `invalid_request` 不再到 Scanner。守卫 6 例(含 AST 断言 REST 无
  字面量重声明 + REST/MCP 逐位一致)+ 变异 baseline 绿→2 红→还原绿
  + 邻接 138p/7s + ruff 零基线。**版本**:BREAKING + minor 2.2.0
  (operator 裁决;注意与 Phase 383 走 major 的先例有意偏离,依据影响面
  为零)。**quick 双引擎 strict gate 本树重跑全绿**:sync
  36/0/28/0(0 SKIP)、async 36/0/27/0(1 SKIP),FP0/FN0/ERROR0、
  性能预算 PASSED;全量未单独重跑(只改 REST 边界,398 full 仍成立,
  不冒充 399 全量)。环境事件:TEMP 指 system temp 时扫描子进程报告
  写入被拒致反复重试「满 CPU 无结果」,TEMP/TMP 指到
  `.cache/xssentinel/tmp` 即恢复(159s)。事实表
  `benchmark/results/phase399_rest_dom_engine_20261117.json`,
  详见 CHANGELOG `[2.2.0]` 与 OPTIMIZATION §8.30。
- **[Unreleased] / Phase 398(2026-11-15,CLI `--dom-engine off` 契约对齐——N 处声明收口)**:
  承接 397 明确留下的观察项(§8.28「本轮不扩 CLI 面」)。**先量再修**:
  `dev/_p398_contract_probe.py` 用真实入口量 5 值 × 5 面(CLI
  `build_parser` 的真实 action、MCP 真实 schema、REST 真实
  `_handle_create_scan` + 只回答 `create`/`start` 的替身、两侧真实
  `_resolve_dom_engine()` 哨兵、中英 README),事实表
  `benchmark/results/phase398_dom_engine_contract_20261115.md`。
  **`off` 被 CLI 以 `invalid choice` 拒(rc=2)而 MCP 接受**;中文
  README 只列三个值。**量出记账外的一处**:REST 对 `dom_engine`
  无值域校验,`bogus` 也 202 直通 `Scanner` 并静默构造真 Chromium
  (与 397 修掉的「off 被忽略」同形)——收紧会拒绝今天被接受的
  请求,**列独立一轮,本轮不修**。修:`__main__.py` choices 补
  `off` + help 对齐 MCP 描述,中英 README 同步用法;**不改默认值
  `auto` / 判定层 / 语料 / 预算 / REST 契约 / 其它 CLI 参数**,
  只增合法值 ⇒ 新增能力非 BREAKING。**同一量具复测**(另存
  `...after...` 不覆写修复前证据):`off` 从拒 → 接受、`bogus`
  仍拒、default 不变,MCP/REST/core 逐位不变,真实 CLI 子进程
  rc=0 / rc=2 / `--help` 显示四值。守卫
  `tests/test_phase398_dom_engine_contract.py` **6 例**(从真实
  parser / MCP schema / README 花括号读值域断言三处集合相等、
  集合增删即红、真实 `parse_args` 接受每个声明值、两侧解析器对
  每个值逐位一致、两处描述都解释 off、英文同步;「两边都认」
  不引入豁免名单)+ 变异 `dev/phase398_mutations.py` **4/4**
  (CLI/MCP/中英 README 各删 off,baseline 绿→mutated 红→
  restored 绿,字节还原)。`README.en.md` 故意不列全量值域以避免
  第五处声明。**仍开放**:REST `dom_engine` 值域校验(独立轮)。
  四档 strict gate / range4 / ruff 数字见 CHANGELOG Phase 398 验收节;
  range3/邻接组/全量分批门本轮未跑(只改 CLI choices 与 README,
  不碰判定层/语料/预算/REST),理由与口径同见该节。
- **[Unreleased] / Phase 397(2026-11-15,`dom_engine="off"` 契约修复——parity 红门归零)**:
  396 留下的第二个红门(parity 全矩阵 `pos-sri-01`)定谳并关闭,**同时推翻
  396「390–395 期间某轮使其复现 / 环境时基观察项」的定性**。8 臂同量具
  对照(`benchmark/results/phase397_bisect_20261115.json`):把 2.1.0 以来
  改过的 4 个产品文件**全部**还原仍分歧且逐位一致,只有两侧补 `off` 分支
  的 `off_fixed` 臂收敛 ⇒ 与版本无关。根因是**公开契约从未实现**:MCP
  input schema 白纸黑字写 `"off" disables the DOM layer`,`AsyncScanner`
  默认就是 `off`,而 sync / async 两份手写 `_resolve_dom_engine()` 只处理
  `static`/`auto`,`off` 直接落到 `DynamicDomAnalyzer` 构造 ⇒ operator
  说「不要浏览器」,只要 Playwright 可导入照样跑真 Chromium;sync 侧被
  Phase 353 `_browser_pointless` 门掩盖、async 无此门(390 已记账的
  设计),一侧暴露 —— 同一族「同一契约手写两遍」。390 测到「不复现」
  是那次浏览器构造失败被 `except Exception` 吞掉(`available()` 只查
  `find_spec`),时基成分来自这里,但触发开关是可修契约而非不可控噪声。
  修:两侧各补 `if de == "off": return None`(不改默认值、不改 CLI/MCP
  默认 `auto`、不改 353 门 / 判定层 / 语料 / 预算 / CLI 契约)。
  **行为面勘误(全量门实测)**:`AsyncScanner` 默认就是 `off`,隐式路径
  同样受影响,不是初稿写的「只在显式 `off` 时」;产品 CLI/MCP/REST
  显式 `auto`、`evidence_shape_sweep` 显式 `static` 不受影响,full
  194 双引擎验证 `auto` 路径不变。守卫 6 例(哨兵 analyzer 把「是否
  构造浏览器」与本机 Chromium 可用性解耦;第 6 例源码级钉住三个 DOM
  交付守卫的 async 构造点必须显式 `auto`)+ 变异 2/2
  + 邻接 65 passed / 0 skipped;事实表
  `benchmark/results/phase397_dom_engine_off_20261115.md`。**两处刻度自
  纠正**:事实表曾引用不存在的 `phase397_sri_control_*.json` ⇒ 改注为
  396 带日期的 `phase396_sri_control_20261115.json`,不冒充本轮产物;
  守卫 docstring 的「7 arms」⇒ 7/8 臂(第 8 臂 `off_fixed` 收敛)。
  **全量分批门首轮 315/319 / RC=4 / skip 13 例 6 文件**:3 个红是
  **真回归**(`test_phase215` / `test_phase209` / `test_phase214` 的
  async 臂直接构造 `AsyncScanner` 用默认 `off` 却断言 `dom_dynamic`),
  A/B 三臂(红→绿→红、字节还原)定谳 **FIX-CAUSED**,修法只给三个
  测试构造点补 `dom_engine="auto"` 与 sync 臂对齐、复跑 14p/0s;
  第 4 个红是 `PYTHONPATH` shim 的 `sitecustomize` 权限错误污染 CLI
  stderr 断言,清空后单文件 34p/0s。**仍开放**:CLI `--dom-engine`
  choices 无 `off` 而 MCP schema 有(同一契约两处声明的既有漂移),
  本轮不扩 CLI 面。**修后全量门重跑 319/319 文件绿 / 470s /
  0 失败 / skip 13 例 6 文件(2 整文件零贡献)**,与首轮 315/319
  一起报;四档 strict gate、parity 门转绿与**环境事件**见
  CHANGELOG Phase 397 验收节。带日期的 396 / 390 原文保留不改,
  以本条与 Phase 397 勘误为准。
- **[Unreleased] / Phase 396(2026-11-15,NodeGoat 存储流——零请求静默退出归零)**:
  395 记账 (c) 的推测**推翻**:真实 CLI 入口打点证明 `_send` 从未被调用,
  stored pass 确实跑了,是页面抓取 `cache_get=True` 命中**被污染的 GET LRU**
  (L8_cookie canary 合法弹回的 7208 字节登录页 200 被按 URL 唯一 key 缓存)
  ⇒ `discover_write_faces` 只见登录表单 ⇒ `faces=0 / ran=0`。修:该处改
  `cache_get=False`,与 `scanner_stored.py` 所有 view GET 一致(同一契约手写
  两遍家族漏掉的那一份)。**同一量具四臂**:baseline 3 findings→真实产品
  改动后 4 findings,层集合多出 **`stored`**,认证页存储型 XSS 端到端打通。
  395 记账 (a)(预算耗尽跳过 stored-auto)在 `--max-requests 12` 下**未复现**
  (47 次 BudgetExhausted 被层内消化,异常没冒泡置 `stopped=True`),不动预算
  语义、不宣称已修。守卫 4 例 + 变异 1/1 + 邻接 59p/3s;事实表
  `benchmark/results/phase396_stored_flow_20261115.md`。终树电池数字与
  **两个红门的如实交代**见 CHANGELOG Phase 396 验收节。
- **[Unreleased] / Phase 395(2026-11-15,parser 收口轮——最后一行漏报归零)**:
  394 留下的唯一语料漏报(polyglot 级联嵌套)根因实锤:**`<!-->` /
  `<!--->` 是 WHATWG 13.2.5.6 的空注释立即闭合**(abrupt-closing-of-
  empty-comment),旧规则只认 `-->`/`--!>` 结尾,把 `/*<!-->…` 之后的
  全部余量当未终结注释吞掉——`<K/contentEditable/autoFocus/OnFocus=…>`
  在解析树里根本不存在。修:`<!-->`(i+=5)与 `<!--->`(i+=6)立即闭合,
  `<!--x` 未终结语义不变(带 note → judge 走 unknown 诚实延迟)。
  **同一量具复测(r5)**:missed 1→**0**(understatement 2.1%→**0.0%**),
  overstatement 0.34%(7 行 handler-执行-但-无-对话框,口径边界非缺陷)
  ——**分类器在 202 向量 × 12 上下文上与 Chromium 对话框 oracle 完全
  对齐**,unknown 190 为诚实延迟。守卫 `test_phase395_empty_comment.py`
  4 例 + 变异 1/1。**NodeGoat 存储流调查(记账,不修)**:394 cookie
  粘性修复后端到端会话存活已验证(jar 单值 pin、主扫描认证成功),但
  存储检测仍未触发——trace 定位三个独立机制:(a) 预算耗尽时 stored-auto
  整段被跳过(间歇),(b) L8_cookie canary 合法弹回一次(设计行为,394
  回 assert 已恢复),(c) auto fetch 零请求静默退出(`_send` 未抛,
  逐请求打点 40 行在案)——stored-auto × 预算 × 认证交互网,**独立
  一轮**。§8 项 8–11 复核:已在 Phase 383–385 全部收口(#8 已做、#9
  评估为不做、#11 NO ECHO),无新工作。环境:NodeGoat 门禁端口随排除段
  漂移(18946 今日 10013 → 改 20506),run_nodegoat 内部烤页服务改
  port 0。终树电池数字见 CHANGELOG Phase 395。
- **[Unreleased] / Phase 394(2026-11-15,验证驱动综合优化轮——三流)**:
  承接 392/393 的验证结果,一次收口。**①勘误**:392 的 CLI 缺陷候选
  「`--batch -o FILE` 静默无输出」**撤销**——干净实验实测为 Phase 88
  设计行为("Report path **or directory** for --batch":带扩展名时每目标
  报告写入 FILE 父目录,392 轮当"残渣"删掉的 `http_127.0.0.1_18946_*.json`
  就是那些报告,当时只检查了 FILE 本身);契约由
  `test_phase394_cli_batch_output.py` 钉住。**②Fixed:`-b` 会话被探针
  Set-Cookie 静默顶掉**(候选②):`Requester` 构造时快照操作者 cookie,
  `_send`(两引擎唯一请求收口)每响应后回 assert;未 pin 的 jar 照常
  采纳新 Set-Cookie(回归钉),刻意重登录走全新 Requester 不打架。
  **③Fixed:sandbox 分词器 invalid-first-character 恢复**(WHATWG
  13.2.5.1,`<<SCRIPT>` 语料行 oracle 弹窗而 sandbox 报 inert 的根因):
  `<` 后非字母非 `?` 只吐 `<` 文本并重新消费;宿主 iframe 加入可聚焦
  集合(srcdoc 引号 breakout 后 autofocus/onfocus 落在 iframe 上,实测
  弹窗;`<frame>` 未测量故意不加)。**同一量具复测(r4)**:missed 3→**1**
  (understatement 2.1%→**0.69%**)、overstatement 保持 **0.34%**;
  最后一行漏报 = polyglot 级联嵌套,列下一 parser 轮唯一残余。验收:
  三流守卫 10 例 + 变异 3/3 + sandbox 套件 34 passed + requester 邻接
  29 passed + 终树电池(range3/range4 + quick/full strict 双引擎 +
  全量分批门)数字见 CHANGELOG Phase 394 验收节。
- **[Unreleased] / Phase 393(2026-11-14,判定修复轮,sandbox.py 五处)**:
  承接 392 量出的差距,按「测量 → 修 → 同一量具复测」落地。**先仲裁再修**:
  裁决探针证明 392 记录的"过判"族(svg onload 未引号属性/autofocus/
  animate onend)在浏览器里确实执行 ⇒ 392 的 r1 oracle(共享 context
  分块并发)自身有假 inert 偏置(169 争议行 14 行 inert→exec)⇒ oracle
  升级(每页独立 context + context 级对话框 + about: 放行)并全量重跑
  r2(2433 页 / 1003s;r1/r2/r3 备份,oracle 变量与 sandbox 变量分开
  归因)。真正成立的五类缺口全修:① token-less script 归属缺口 →
  **unknown**(defer;引擎恒带 token 不受影响,verifier.py:734);
  ② 空 src 的 onerror → live(旧"no load attempted"是推断,实测
  `<audio src/onerror>`/`<img src/onerror>` 都弹窗;src **缺席**保持
  inert);③ `<source>` 子元素启动 load → onloadstart live;④
  `<template shadowrootmode=open>` 是声明式 shadow root,内容不再按
  死区;⑤ contenteditable 使任意元素可聚焦 + 属性名大小写折叠(旧
  attrs 字典漏驼峰)。**同一量具复测(r3 = `--resandbox`,oracle 不动)**:
  overstatement 6.0%→**0.34%**(123→7)、understatement 12.4%→**2.1%**
  (18→3),其余走 unknown 诚实延迟(+124)。残余 7 过判 = handler 执行
  但无对话框(fetch/eval 型)+ srcdoc 引号解析分歧;残余 3 漏报 =
  解析器级 gap(`<<SCRIPT>`、srcdoc 属性续接等)——引擎 CLI 在去重页
  0 findings(烤页不在检出面上),**解析器不动,修复列下一 parser 轮**。
  验收:Phase 393 守卫 7 例 + 变异 5/5 + sandbox 邻接回归 69p/3s +
  range3/range4 行为契约 exit 0 + quick strict 双引擎全绿(sync 64
  scored 0 SKIP / async 63 scored 1 SKIP,FP0/FN0/ERROR0)。**环境新
  事实**:Windows 排除段已覆盖 18923–19822 连续区间(Hyper-V),传统
  门禁端口 18931/18932 与多数 18xxx 全 10013 ⇒ runner/oracle 默认改
  port 0 动态分配,range4 走 `XS_RANGE4_PORT=20504`;终树门禁(full 194
  双引擎 + 全量分批门)见 CHANGELOG Phase 393 验收节。
- **[Unreleased] / Phase 392(2026-11-14,外部测试语料轮,产品代码零改动)**:
  应「全方面找别的开源项目的测试来测本项目」——把五个第三方语料
  (PortSwigger 2026 cheat sheet、SecLists 六个 XSS 表、PayloadsAllTheThings
  四份、OWASP Filter Evasion、html5sec/Mario)的 **202 个唯一向量**逐条投进
  反射上下文,M1 用引擎 verify gate 的同一个 `judge(page, token="",
  sink="parser")` 分类,再拿真 Chromium load 态对话框逐页定谳(oracle
  1146s / 2635 页,控制页健全性不过就 ABORT 不发布);重算后
  **understatement 13.0%(16/123)、overstatement 6.5%(134/2067)、
  activation_inert 234 单列**(href-javascript: 的 load 态 inert 是诚实
  语义)。可行动差距已量出:script 体无编译检查即判 live(x97,最大
  over-statement 族)、srcdoc 整文档解析(x19)、audio error/loadstart
  事件、声明式 Shadow DOM slot onslotchange、可选链 `alert?.(1)`
  (本条差距清单的归因随后被 Phase 393 仲裁修正:最大过判族实为
  token-less 归属缺口 + r1 oracle 假 inert,见上条)。
  M2 上下文孪生页端到端:**vuln 8/8 high 检出、context-correct 安全孪生
  4/4 干净**(naive 转义 href 孪生被报 high 是引擎对、孪生错——HTML 转义
  不中和 javascript: URI,与 367/369 同课);同台事实表:nuclei 8/8 检出
  且安全孪生 0 误报(0.4s/例)、dalfox 0 检出(2 例 45s 超时)。M3 接入
  **OWASP NodeGoat**(官方 zip+官方种子,本机无 Docker/WSL/Java11+/PHP
  下唯一可跑的真实第三方应用):官方源码答案键 + oracle 定谳 7 形状
  (5 exec / 1 inert=marked sanitize 实测 / 1 activation),引擎带
  `-b` 会话实际扫的是登录页(**探针 Set-Cookie 污染 jar 顶掉操作者会话**,
  认证静默丢失家族),dalfox/nuclei 事实行全 0。**两个 CLI 缺陷候选**
  已实测记录:`--batch -o FILE` rc=0 且无文件无 stdout(静默无输出)、
  上述 cookie jar 污染;本轮只记账不修(修要走自己的门禁轮)。
  (候选①随后被 Phase 394 **撤销**:实测为 Phase 88 设计行为——每目标
  文件写入 FILE 父目录,当时只检查了 FILE 本身;候选②由 Phase 394 修复,
  见上条。)
  h5sc/vectors.txt 与 SecLists XSS-Vectors-Mario.txt 实测同一捆绑,
  只采一份不重复计数。证据 `benchmark/results/phase392_external_corpus_20261114.{json,md}`、
  `phase392_nodegoat_20261114.{json,md}`;守卫 `tests/test_phase392_external_corpus.py`
  + `test_phase392_nodegoat.py` 共 **24 例**,变异 `dev/phase392_mutations.py`
  **8/8**(其中三例先暴露守卫盲区:改数据定义不影响冻结证据,改为源码级
  钉子后全过);首轮测量代码两处自我纠正(classify 拆 activation_inert、
  script_dq 退出 escaped 孪生)以 `--recompute` 重算完成,原始测量行未变、
  弃用行留档 `recompute_discarded`。**不与 XSSMaze/194 矩阵/bWAPP/Juice
  Shop 任何数字并列**;nodegoat 运行期向靶场写入 1 条 memo + profile 覆写
  (runner 内已披露)。
- **[Unreleased] / Phase 390(2026-11-14,勘误轮)**:把 2.0.1 / 2.1.0 记下的
  parity 全矩阵 2/194「行为性分歧 / sync 侧潜在挖矿 FN」用四臂测量定谳为
  **量具缺陷**——opt-in 门给 manifest 声明无可见参数的用例塞了合成
  `q=probe`,触发 sync 的 Phase 353 自适应挖矿门而 async 无此门;换成
  runner 的真实形状(`params={}`)或任一文档化 env 逃生舱,双引擎逐位一致。
  另一例 `pos-sri-01` 的 `dom_dynamic high` 在 2.1.0 终树四臂**不复现**,
  不宣称已修、留作环境/时基相关观察项。只改 opt-in 量具
  (`tests/test_parity_full_matrix.py` 的 `_gate_params`,10 例受影响、
  184 例逐字节不变),**产品代码零改动**;守卫 + 变异 + 全量 194 复测数字
  见 OPTIMIZATION §8.21 与 CHANGELOG `[Unreleased]` 勘误。带日期的
  2.0.1 / 2.1.0 / §8.17 原文保留不改。**仍开放**:`pos-sri-01` 是否在别的
  树/环境复现(观察项)、`<div onstart>` 等未测形状、PyPI Trusted
  Publisher(归属者外部待办)。
- **2.1.0(2026-11-13,minor,交付轮)**:承接 Phase 387–389。按「新增能力走
  minor」定级(strict gate 新增墙钟预算维度),无破坏性变更。**387**:四档
  实测基线 + 推导 ceiling + 未测量组合一律 UNBUDGETED,守卫/变异/源码断言
  齐全。**388**:推翻 2.0.1 记下的「fn_net 2 个真 FP / L7 降档」——用
  finding 自己载荷 + 真 Chromium 的 72 臂矩阵证明 8/9 形状是真阳性,按
  原方案修会制造 FN;带日期原文用 `[Unreleased]` 勘误 + §8.17 旁注纠正,
  不改写历史。**389**:把唯一 verifier-only 的 `marquee/onstart` 在沙箱
  事实表标 `inert`,让既有 veto 收回确认;元素 × 属性 pair(不误伤
  Phase 362),语料集合不动;同量具重测 `verifier_only` 1→0、
  `true_detection` 8→8,全量 194 两档 FP0/FN0/ERROR0。逐项见
  OPTIMIZATION §8.18–8.20 与 CHANGELOG [2.1.0] 验收节。**仍开放**:parity
  全矩阵 opt-in 门 2/194 存量分歧、`<div onstart>` 等未测形状、PyPI
  Trusted Publisher(归属者外部待办)。
- **2.0.1(2026-11-13,patch,优化测试轮)**:承接 Phase 386——重跑
  Phase 334 窗口审计量出 `<svg><a xlink:href=javascript:...>` 被分类器误判
  `html_attribute_dq`,而 sandbox 的 `JS_URI_ACTIVATION` 早已按测量建模该
  sink(Chromium oracle 真实点击复测弹窗)⇒ 分类器把 `xlink:href` 并入
  URL 上下文(执行语义仍在验证器元素+属性表;非 anchor 的 xlink 形状
  假阳防护钉守卫)。svg_context 该死槽转激活类活槽。守卫 5 例 + 变异 1/1 +
  邻接组 54 绿 + 四档 strict gate 全绿 + 全量分批门 **305/305**(skip 13 例
  /6 文件,2 整文件零贡献)。同一测量轮以实测关闭三个遗留:Phase 334 死槽
  处置(引擎忠实口径重测 + oracle:无可换活向量,html_comment 候选为审计
  伪影)、Phase 251 UTF-7 href 遗留(fn_net fn_candidates=0)、§1.1 lint
  缺口(四目录全绿)。新记账:fn_net 的 2 个 polyglot FP 候选(浏览器证伪,
  L7 降档列下轮候选)、parity 全矩阵 opt-in 门 2/194 存量分歧(A/B 定谳非
  386 引入,sync 挖矿 FN 归因列下轮)。逐项见 OPTIMIZATION §8.17 与
  CHANGELOG [2.0.1] 验收节。
- **2.0.0(2026-11-13,major,交付轮)**:唯一遗留 P0 清零 + P2 评估收口。
  **#1 授权范围默认策略已由归属者拍板为 TOFU(首用钉定)** 并落地
  (Phase 383,`feat(mcp):` 提交):operator 启动时以 `--allow-host` /
  `XSSENTINEL_MCP_ALLOW_HOSTS` 钉定范围(或 `--allow-any-host` 显式回
  open 并强披露),默认首个**成功**的带 url 调用钉定其 origin,跨 origin
  调用拒绝且**零请求外发**;legacy 帧同拒;范围配置时 sync 重定向边界随之
  开启,被拒跳转入结果的 `boundary_stops`。**破坏性变更**:MCP 多 origin
  会话需显式配置,按版本策略走 major ⇒ 2.0.0(单靶工作流、CLI、REST
  `/api/v1/scans` 契约不变)。Phase 384 凭据回显审计结论 **NO ECHO**
  (守卫钉住),其 unreachable 臂量出并修复 `xssentinel_discover` 对不可达
  目标谎报成功的真缺陷(补 `_preflight`,Phase 327「假无发现」家族)。
  Phase 385 成功结果带 `run_id`/`elapsed_ms`(双通道同源),`budget_used` /
  `next_actions` 评估为不加、#9 评估为不做(P2 全部收口)。三个 Phase 各有
  守卫(13/4/5 例,0 skip)与变异对照(6/6、2/2、3/3),MCP 回归组全绿,
  ruff 全仓零基线。门禁实测数字记 CHANGELOG [2.0.0]「验收(交付轮)」,
  不在本文件复制。历史 tag 缺失已补齐(v1.4.2/1.4.3/1.4.4/1.5.0 +
  本版 v2.0.0);**PyPI Trusted Publisher 仍是外部待办(归属者在 GitHub
  仓库设置里配)**。
- **1.5.0(2026-11-12,minor)**:承接 Phase 372–381 的 MCP 接入面增量与
  Phase 382 的独立浏览器事实表。Phase 376 新增客户端超时协商、
  Phase 377 新增 2 个仅现代帧异步扫描工具,按「新增能力走 minor」定级;
  无破坏性变更(legacy MCP 帧逐字节不变、CLI 契约不变、判定层零改动)。
  `__version__` 与 CHANGELOG 最新章节同源,`test_doc_gate_parity`
  的版本守卫绿。**仍是 `[Unreleased]` 的旧条目已全部归入 1.5.0 章节**,
  文件顶部保留空的 `[Unreleased]` 段(守卫要求)。
- **交付轮收口(2026-11-12)**:5 个此前未跟踪产物按性质拆开——
  `benchmark/run_juice_render.py` + `juice_render_20261110.{json,md}`
  入库(Phase 382 事实表,守卫 `tests/test_phase382_juice_render.py`
  8 例,变异对照 baseline 绿 → 改 counts 红 → 字节还原绿);11-10 的
  两份 HTML 报告移进 gitignore 的 `benchmark/results/_local_archive/`,
  仅本机留档。Phase 382 的测量树是 `edfe91d`,**不是 1.5.0 终树**,
  只作外部效度补充、不冒充终树跑分。
- **交付轮发现的打包缺陷(已修)**:`pyproject.toml` 的 `data/*.json`
  通配把 gitignore 掉的 `llm_state.json` 打进了本机实测 wheel(同类
  `llm_providers.json` 含密钥,存在时也会被带走)——`.gitignore`
  对构建没有约束力。新增 `exclude-package-data` 与守卫
  `tests/test_package_data_hygiene.py`,把 `.gitignore` 与排除清单
  逐项钉在一起(单向漂移 / 集合增删 / 名单被掏空都红);变异对照
  baseline 绿 → 改一个排除项红 → 字节还原绿。
- **交付前门禁(2026-11-12,终树自跑)**:逐项数字与 skip 数统一记在
  CHANGELOG [1.5.0]「验收(交付轮)」与交付验收报告,不引用 11-10
  在 `edfe91d` 旧树上跑出的 299 文件 / 194 例数字。同期邻项目
  `D:\qoder\vuln-agent` 有并发测试批,按既有协议对红项做 A/B 归因。
- **本机环境新事实(2026-11-12)**:`%TEMP%` 对本进程不可写,
  `tempfile.gettempdir()` 会静默回退到仓库根;而精度门
  `dev/gate_run_scratch.py` 直接读 `os.environ["TEMP"]`,结果目录
  写不进去。本轮把 `TEMP`/`TMP` 指到工作区外的可写 scratch 再跑门禁。
  `pip wheel` / `pip install --target` 在本机仍是数分钟级挂起(与
  「pip 通路病态」同一形态),构建验证改用 `uv build --wheel`
  + 解压 wheel 做等价安装冒烟,不改产品/测试代码。
- **1.4.4(2026-11-08,patch)**:承接 Phase 364–371(反射形状补齐、Agent 接入面两处
  FN 修复、契约收敛、`javascript:` 重定向与链接 scheme、测量口径、架构瘦身与
  层注册补齐),无破坏性变更,按「只修缺陷/补齐既有能力走 patch」定级。
  `__version__` 与 CHANGELOG 最新章节同源,版本同源守卫
  `test_doc_gate_parity.py::test_changelog_latest_version_matches_package_version` 绿。
- **交付状态(2026-11-08 收口后)**:收口前工作区实测 20 M + 36 未跟踪;现已按
  **依赖闭包**拆成 5 个本地提交(`f1126bf` 形状/引号契约/架构搬运、
  `e071677` Agent 接入面、`da5ee89` 重定向与链接 scheme、`d07717b` 测量口径与
  靶场证据、本条所在的 release 提交)。未按单个 Phase 做 hunk 级拆分:
  `scanner.py` / `verifier.py` 同文件跨 364/367/371,拆开会出现
  「Scanner 引用尚不存在的 ShapesMixin」的不可运行中间树;理由写进首个提交信息,
  每个提交都是可导入可运行的完整闭包并在信息里列全所含 Phase。
  **已推送(2026-11-08 晚)**:`git push origin main` 把这 14 个提交推到
  `origin/main`(`67a1a80..13b0227`),远端不再停在 Phase 358 时代。
  ⇒ 11-07/11-08 的全部跑分仍是**测量当时的 WIP 树**数字,不是已发布 1.4.3
  的成绩(与是否推送无关)。Phase 372–374 为之后的 `[Unreleased]` 增量
  (代码提交 + 文档收口共 2 个,见下条),完成后一并推送到 `origin/main`。
- 口径复测(2026-11-08,含本轮 4 个新源码文件与 7 个新守卫):源码
  **140 文件 62,332 行**;测试按 tracked + 本轮待提交 `test_*.py`
  **290 文件 65,530 行**。口径仍是 `wc -l` 物理行、排除 `__pycache__` /
  `tests/_pytest_tmp/`,包含未跟踪的本轮文件(与 11-06 那行「tracked +
  本轮待提交」一致)。带日期的历史记录保留不改。
- Phase 364–371 落地(逐轮报告见 `benchmark/results/*_2026110{7,8}.md`):
  - **364**:三类反射形状漏报(srcdoc 实体拼写 handler、JS 响应反引号回调、
    参数名注入),现位于 `core/scanner_shapes.py`;守卫 `test_phase364_shapes.py`。
  - **365/366**:由外部 CLI 型智能体 e2e(`agent_cli_e2e_20261107.md`)量出的
    两处接入面缺陷——MCP `profile` 工具对 GET 已有同名参数应替换而非追加
    (否则首参遮蔽探针、假阴性跳过整次扫描)、`propose` 生成超时改由
    `llm_timeout` 配置驱动(硬编码 60s 会把 68.5s 的正常响应误报成
    「LLM pool exhausted」)。守卫 `test_phase365_mcp_url_parity.py` /
    `test_phase366_propose_timeout.py`。
  - **367**:sync/async 两处手写的引号逃逸探针与判级收敛到
    `core/quote_escaping.py` 一个定义,守卫同时钉行为与两引擎调用点源码。
  - **368**:`302 Location: javascript:...` 被 requests 自动跟随并抛
    `InvalidSchema`,健康目标被标 `partial`;新增 `core/url_safety.py` 共享
    白名单,每跳拒绝非 http(s) 目标。XSSMaze 86 例分层抽样实测
    `partial 14→0`、`requests_failed 26→0`,TP59/FP0/findings 96 逐位不变。
  - **369**:sync/async 各手写一份 scheme 黑名单且已漂移(async 漏 `tel:` /
    `data:`,两者都漏 `vbscript:` / `blob:` / `file:` 与大小写·Tab 变形),
    统一为 `is_crawlable_link` 白名单;合法相对/协议相对行为不变。报告先纠正
    上一轮「静态扫描列缺口」的误判(上游已有防线),不为修而修。
  - **370**:`dev/_xssmaze/wrapper.py` 增加 opt-in `XSSMAZE_POST_AWARE`,
    让官方 runner 的 POST-only 端点拿到 POST body;默认关闭、旧口径逐字节可复现。
    **这是测量口径修复,不是检测能力提升**,新数字不得与旧口径直接比较。
  - **371**:`scanner.py` 2793→2624 行(预算 2650),Phase 364 三个形状方法
    **字节级原样**搬进 `scanner_shapes.py`(`ShapesMixin`,7650 B / 171 行
    sha256 一致),同步登记 `BUDGETS` / `HIERARCHIES`,纯搬运零逻辑改动;
    广回归顺带抓到 Phase 364 的 3 个 layer id 未注册 `coverage.LAYERS`
    (统计/摘要/覆盖矩阵全看不到),按「两处同时注册」补齐——AGENTS.md 记的
    同一课**第三次踩**,根因是前几轮回归组漏了层注册守卫。
- **Phase 372–374(2026-11-08 晚,`[Unreleased]` 增量)**:按
  `docs/OPTIMIZATION.md` §8.5 的建议顺序先做零争议的三件,全部落在
  `api/mcp_server.py`,**不碰扫描判定、不改 legacy 帧字节**:
  - **372 / §8.1-2**:`tools/call` 的错误结果追加
    `structuredContent.error{code,message,field,accepted_keys,hint,retryable}`,
    分类只认本模块自己生成的句子(精确前缀 + 窄子串),覆盖未知工具/未知键/
    缺必填/非法 URL/参数类型/超时/执行失败。**仅 modern 帧附加**:
    `test_phase324_mcp_http.py` 钉住 legacy 错误结果没有 `structuredContent`,
    Phase 358 的逐字节契约优先。
  - **373 / §8.1-3**:`run_scan_tool` 的 `[:200]` 补
    `total_findings` / `truncated` / `truncation_hint`;`run_param_mine_tool`
    同类切片补 `total_discovered` 等并把 `discovered_count` 统一为
    **实际返回条数**(此前是总数却只返回前 200 行);两个 `outputSchema`
    同步扩字段。
  - **374 / §8.1-5**:7 个工具补 `title` + `annotations`
    (readOnly=false / destructive=true / openWorld=true / idempotent=false),
    **只在现代 `tools/list` 附加**,`TOOL_DEFINITIONS` 本身不变。
  - 守卫 `test_phase372_mcp_structured_errors.py`(16 例)、
    `test_phase373_mcp_truncation.py`(9 例)、
    `test_phase374_mcp_annotations.py`(4 例),各有 AST 钉子锁 modern-only 接线。
    变异对照 `dev/phase372_374_mutations.py` **3/3 通过**
    (baseline 绿 → 删结构化字段 / 置 `truncated=False` / 关掉 modern 分支
    各自红 → restored 绿),源码字节已还原。
  - 回归口径(2026-11-08,本机):17 文件 **167 passed / 1 failed**、1 rerun,
    97.8s;唯一的红是
    `test_phase327_mcp_scan_budget.py::test_scan_against_a_blackholed_port_fails_fast`
    —— `_ToolTimeout` 在 30s deadline 到期时冒出(单跑 68.8s)。**A/B 对照**:
    把源码换回 `HEAD`(改动前)跑同一用例,同样 FAILED、同样异常与耗时
    ⇒ 定性为本机 loopback 劣化期环境形态,不是本轮回归;按「未验证」记账,
    不当绿也不当回归。ruff 全仓 `All checks passed`;三守卫恢复后单跑
    **29 passed / 0 skip**。**未跑全量分批门禁与四档 strict gate**:
    本轮是 MCP 接口层纯增量,判定面零改动,但按「绿和跑过是两个词」不拿
    旧 run 的数字顶上,下轮环境干净时补跑。
- **Phase 375 / §8.2 #6(2026-11-08 晚,`[Unreleased]` 增量)**:进度通知补
  `total` 与单位说明。`_tool_call` 用 scoped emit 包装:估算
  `max_payloads × params`(复用 Phase 365 的 `split_target_url`,不另写 URL
  解析;`param_mine` 用 `max_params`),`total` 只是**估计上界**,真实请求超过
  估算时自动抬高,保证 `progress <= total` 恒成立;每条通知带 `message`
  说明单位。`progress` 语义仍是「已发请求数」,起始信标仍是 0,
  无 `progressToken` 时 `emit=None`、**零通知**;`_RequestGuard` / runner /
  transport 一律未改。守卫 `test_phase375_mcp_progress_total.py`(4 例,
  真实 stdio 会话),变异对照 `dev/phase375_mutation.py` **1/1**
  (删掉 `total` → 红 → 还原绿,源码字节已还原)。回归口径(2026-11-08):
  19 文件 **182 passed / 1 failed**、1 rerun,102.3s;唯一的红仍是上一条
  A/B 已定性的 `test_phase327` 环境形态——该用例直接调 `run_scan_tool`,
  不经过 `_tool_call` 的 emit 包装。ruff 全仓零基线。未跑全量分批门禁与
  四档 strict gate,理由同上条。
- **Phase 376 / §8.2 #4 ①②(2026-11-09,`[Unreleased]` 增量)**:客户端超时
  协商 + HTTP 断连中止。`server/discover` 声明 `recommendedTimeoutMs` /
  `defaultMaxSeconds` / `clientBudgetMetaKey` / `budgetPolicy`;现代帧的
  `params._meta['io.xssentinel/clientTimeoutMs']` 按 `min(client,
  max_seconds)` 折进**既有**预算(只能缩短、不能抬高),成功结果回显
  `effective_max_seconds`,超时错误点名客户端旋钮;默认 300s 收敛为单一常量
  (schema / runner / discover 同源)。legacy 帧行为不变,非法或过小的声明
  显式结构化报错且**不启动扫描**。HTTP 侧新增 opt-in
  `_ClientDisconnectWatcher`:仅 `tools/call` + 真实 socket 时用 `MSG_PEEK`
  窥探 EOF(pipelined 数据不误判),命中后复用 stdio 既有的 `cancel_event`,
  在 `_RequestGuard._tick` 的下一请求边界停止外发;Flask 适配器与单测上下文
  无 socket ⇒ 完全不武装。守卫 `test_phase376_mcp_timeout_contract.py`
  **29 passed / 0 skip**(真实 dispatch + 真实 socketpair + 零外发对照),
  变异对照 `dev/phase376_mutations.py` **4/4**,广回归 18 文件
  **296 passed / 0 failed**、102.4s,ruff 全仓零基线。**未跑全量分批门禁与
  四档 strict gate**:判定面零改动,不拿 11-08 的数字顶账;11-09 基线组
  109 例与广回归 296 例全绿、昨晚 A/B 定性的 `test_phase327` 环境形态红
  已转绿 ⇒ loopback 环境已恢复,补跑条件具备。**已补跑 quick 双引擎
  strict gate(2026-11-09 自己跑,带跳过数)**:sync 64 scored **0 SKIP**、
  async 63 scored **1 SKIP**,各 exit 0、FP0 / FN0 / ERROR0(端口
  18931 / 18932)。**full 194 两档与全量分批门禁仍未跑**,不拿 11-08
  的四档数字顶账。
  **#4-③(异步工具)未做,单独一轮**:新增 2 个工具会撞 `len(tools)==7`
  三处守卫与 README「七个工具」声明,且 Phase 358 的 legacy `tools/list`
  逐字节契约要求新工具不能进 `TOOL_DEFINITIONS`,改动面与 ①② 不同
  ⇒ 已于 Phase 377 单独一轮完成(见下条)。
- **Phase 377 / §8.2 #4 ③(2026-11-09,`[Unreleased]` 增量)**:新增 2 个
  **仅现代帧**工具 `xssentinel_scan_async`(提交即返回 `scan_id`、零目标请求)
  / `xssentinel_scan_status`(轮询、`cancel=true`、`include_findings=false`)。
  复用既有 REST `JobManager` 状态机(模块级 lazy 单例,stdio 与 HTTP /mcp 共用,
  不是 REST server 那个实例),worker 直调 `run_scan_tool` ⇒ 轮询结果就是同步
  扫描同一份 compact findings,截断与预算元数据一并透传。`Job` 加可选
  `result_meta`(不进 `to_summary` / `to_detail` / SQLite,REST 契约零变化)。
  **legacy `tools/list` 仍逐字节 7 个工具**,legacy 帧调新工具仍是 unknown
  tool;modern 为 9 个,title / annotations / 双 schema 齐全(4 个既有守卫
  随能力更新、强度不降)。取消或断连的 job 一律 `failed` + 明确原因,
  绝不记成零 findings 的「干净扫描」。`server/discover` 增 `asyncTools` /
  `asyncWorkflow`,中英 README 与 SKILL.md 同步补齐编排说明。守卫
  `test_phase377_mcp_async_tools.py` **17 passed / 0 skip**,变异对照
  `dev/phase377_mutations.py` **6/6**,21 文件广回归 **336 passed / 0 failed**、
  115.0s,ruff 全仓零基线。**full 194 两档与全量分批门禁仍未跑**:判定面
  零改动,不拿旧数字顶账。
- **Phase 378 / §8.2 #7(2026-11-09,`[Unreleased]` 增量)**:现代帧的相同
  `tools/call` 在 TTL(默认 60s,上限 300s)内复用最近一次**成功**结果,
  不再重复外发攻击载荷。键 = `tool + 归一化参数`(schema 默认值先填满、
  别名已折叠、含 headers/cookies),或客户端 `params._meta.requestKey`;
  `cacheScope='none'` 关闭。成功结果 text 与 `structuredContent` 同步带
  `cache_hit` / `cache_scope` / `cache_ttl_ms`,可缓存工具的 outputSchema
  同源声明;`server/discover` 增 `resultReuse`。**失败 / 超时 / 取消一律
  不缓存**,`xssentinel_scan_status` 轮询永不复用,legacy 帧逐字节不变;
  缓存 LRU 上限 128、加锁、进程内,不提供 `public` 作用域(取其他值显式报错)。
  **测试隔离是根因修法**:模块级缓存会让两个同参守卫互相命中,首个实测
  有 10 个 MCP 守卫因此变红 ⇒ `tests/conftest.py` 加 autouse fixture 在
  测试边界调 `_clear_result_cache()`,产品路径零改动。守卫
  `test_phase378_mcp_idempotency.py` **22 passed / 0 skip**,变异
  `dev/phase378_mutations.py` **7/7**,22 文件广回归 **358 passed / 0 failed**、
  116.3s,ruff 全仓零基线。**full 194 两档与全量分批门禁仍未跑**:判定面零改动。
- **终树全量门禁补跑(2026-11-09 晚,树 `00a017d`)**:上面三轮「未跑」的债
  已关闭,完整判词与归因见 `benchmark/results/gate_evidence_20261109.md`。
  四档 strict gate 各 exit 0、FP0/FN0/ERROR0,带跳过数:quick 64 sync
  **0 SKIP** / quick 64 async **1 SKIP**(同日早些)、full 194 sync
  **194 scored / 0 SKIP**(344s,18941)、full 194 async
  **182 scored / 12 SKIP**(343s,18942)。全量分批门 `--jobs 4 --quiet`
  **297/297 文件绿 / 459s / 失败 0**,**skip 13 例 / 6 文件
  (2 个整文件零贡献)**。R1(265/297,32 红)与 R2(261/297,36 红)
  是**环境形态**:35/35 失败日志含 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`、
  **0 个真实 pytest 失败**;A/B 单跑 121 passed 否证 TEMP 假设,
  真因是工作区内 `tests/_pytest_tmp` 的旧 numbered 目录清理撞上
  50 次/turn 删除守卫。修法零产品改动:`dev/batched_gate_scratch.py`
  重定向日志 + `PYTEST_ADDOPTS` 关掉清理 ⇒ R3 全绿。
  **带日期的历史「未跑」记账一律保留不改**,本条只追加新证据。
- **Phase 379 / 真实外部应用靶场(2026-11-09,树 `ba1016c`)**:用官方 OWASP
  Juice Shop v20.2.0 release(MD5 校验一致)作第三方真实目标,
  `dev/juiceshop_external.py` 5 面全 exit 0:**4 面各 1 条 `dom_dynamic` /
  high / `browser-executed`**,REST 面 0(该面独立测得 `reflects=False`),
  控制面 FP 0。对照官方 `challenges.yml` 的 9 个 XSS 挑战**只覆盖 2 个**
  (DOM / Reflected),其余 7 个未投递、既非 TP 也非 FN ⇒ **5 是同一应用的
  5 种调用形态,不是 5 个独立靶,任何率都不得计算**。证据与不可比项见
  `benchmark/results/juiceshop_external_20261109.md`。环境:XSSMaze 因
  `wsl.exe` 被安全策略拉黑 + Docker daemon 不可用而**放弃**(需仓库归属者
  到安全中心解除黑名单);Juice Shop 的 `build/`+`node_modules/` 曾被清空,
  经 GitHub API + `ghfast.top` 镜像取回官方包、MD5 校验、解压 44,140 文件
  (`dev/_*` 被 gitignore,不进版本库)。**跨工具同台对跑未做**(口径与
  hash 路由适配问题,单列一轮),不与 XSSMaze 1013 例 / 194 矩阵 / 商业工具并列。
- **Phase 380 / 真实外部应用上的跨工具事实表(2026-11-10 凌晨,树 `7d3b9f7`)**:
  承接 §8.12「跨工具同台对跑未做」(带日期的历史记录保留不改),在**同一个**
  官方 Juice Shop v20.2.0 真实目标上给 XSSentinel / dalfox v2.13.0 /
  nuclei v3.9.0 喂逐字相同的 5 个 URL,只记各工具实际输出,**不出分数**:
  - 5 面 = 官方 `challenges.yml` 的 2 个挑战 + 2 个独立测得的控制面
    (`/rest/products/search` `reflects=False`、`/redirect` 仅 HTML 转义)
    + 1 个 `pos-derived` 补充观察(`/#/search-result`,**不进分母**)。
    runner `benchmark/run_juice_cross_tool.py`,产物
    `benchmark/results/juice_cross_tool_20261110.{json,md}`。
  - 实测 15 行:XSSentinel 检出 3 / 错误 0 / 23.07s,dalfox 0 / 3 次
    `rc=2` / 29.26s,nuclei 0 / 0 错误 / 902.82s(每例约 180s)。
    **这不是胜负也不是率**:3 个正例的注入点在 URL fragment,HTTP 请求
    根本不携带 ⇒ 请求型工具的 0 是「未测量」不是漏报;两个服务端可达面
    都是真阴性 ⇒ 无 server-deliverable positive,TP / 召回率无分母;
    工具配置亦不同(nuclei DAST 含浏览器模板、本仓适配器无 `--headless`)。
    `scoring_policy` 明确 `FACT TABLE ONLY. No TP/FP/TN/FN or F1`。
  - 守卫 `tests/test_phase380_juice_cross_tool.py` **7 passed / 0 skip**:
    钉住口径全文、summary 无分数字段、每行 fragment 形状必须由
    `_delivery_shape(url)` 真实函数推导(AST 反查函数体不得出现工具名
    白名单)、官方答案键不丢失、`pos-derived` 不进分母、summary 由 rows
    重算、MD 与 JSON 经 `to_markdown` 逐字节同源。变异对照
    `dev/phase380_mutations.py` **7/7**,每个变异只跑一个具名 test node
    (避免「另一条断言红了」的假绿),源码/产物字节已还原。
  - 真实靶场复现抽验(18900 在跑):`--tools XSSentinel` 5 例 22.88s,
    detected 3 / errors 0 / detected_on_server 0,与 00:31 产物逐例一致;
    复现产物落 `benchmark/results/_local_archive/`(gitignore),不覆盖
    正式证据。收口顺手删 runner 一处未使用的 `import time`(零行为变化)。
  - **边界**:商业工具仍零对跑、ZAP 仍 unavailable;本表不与 XSSMaze
    1013 例 / 194 矩阵 / Phase 379 的 `--headless` 结果并列,不改变唯一
    官方跑分口径。验收(本轮自己的运行):守卫 7 passed / 0 skip、
    变异 7/7、回归组 30 passed / 0 skip、ruff 全仓零基线、
    真实靶场复现抽验 5 例;门禁补跑判词见下条。
- **Phase 380 验收补记 / quick strict gate 本轮未完成(2026-11-10)**:
  本轮尝试补跑 `--quick --strict-gate` 双引擎(sync,端口 18931),
  sync 档启动后 **11m34s 仍停在单引擎**:进程 CPU 持续满载
  (624s→681s),scratch 目录无任何逐例报告落盘、无扫描器子进程,
  遂终止,async 档未启动。**未做 A/B 归因 ⇒ 按「未验证」记账,
  不当绿也不当回归**;判定面本轮零改动(只删一个未使用 import),
  不拿 11-09 的四档数字顶账。`full 194` 两档与全量分批门禁
  **本轮未跑**,下轮环境干净时一并补跑并诊断该挂起形态。
- **Phase 381 / 官方 XSS 挑战逐例投递事实表(2026-11-10,树 `f9ec777`)**:
  承接 Phase 379「9 个官方挑战只覆盖 2 个」的空白,在**同一个**官方
  Juice Shop v20.2.0 真实目标上对另外 7 个逐例测量「能不能投递、
  服务端回读成什么」,仍**不出任何率**:
  - runner `benchmark/run_juice_challenges.py` 从目标自带的
    `data/static/challenges.yml` 读 9 个 `category: XSS` 挑战的
    key/name/difficulty/disabledEnv 与 bonus payload(不凭记忆手写);
    产物 `benchmark/results/juice_challenges_20261110.{json,md}`。
  - 实测 7 行:**delivered 2**(`restfulXssChallenge` PUT
    `/api/Products/1` 的 `description` 原样回读、`httpHeaderXssChallenge`
    `True-Client-IP` → `/rest/saveLoginIp` 的 `lastLoginIp` 原样回读);
    **accepted_not_reflected 3**(`persistedXssUserChallenge` 201 但
    username 被改写成 `rc="javascript:alert(...)">`、
    `persistedXssFeedbackChallenge` 201 但 `comment` 被 sanitizer 剥成空串、
    `usernameXssChallenge` legacy 页 200 但 username 参数不回显);
    **blocked 1**(`videoXssChallenge` 官方 hint 要求先拿到另一个 6 星
    文件写入能力,本轮**零请求**、写明原因、不进任何分母);
    **fragment_only 1**(`xssBonusChallenge` 注入点在 URL fragment,
    用官方 bonus payload 跑了一次真实 CLI,1 条 `dom_dynamic`,6.26s)。
    **delivered 只表示「本轮请求自己的响应里字段值等于 payload」,
    不表示浏览器执行**;SPA 渲染与跨工具可达性未测。
  - **三处自我纠正(都是测量口径,不是产品问题)**:① JSON 里引号被转义,
    `payload in r.text` 会把原样存储误判成未回显 ⇒ 改为解析后比较
    **解码字段值**;② 首版用 `/api/Users` 列表与 JWT 快照作回读,
    命中了**前几轮试跑写入的持久化状态** ⇒ 判据收紧为「只认本轮
    请求自己的响应」,列表/快照降为补充字段;③ 本沙箱 Python 子进程
    调 `git` 被 `WinError 5` 拒绝,`_git_head()` 首版静默写
    `tree: "unknown"` ⇒ 改为**拿不到归属就 ABORT**,由调用方传
    `--tree f9ec777`;守卫钉住不得回潮。
  - 守卫 `tests/test_phase381_juice_challenges.py` **9 passed / 0 skip**:
    钉住口径全文与 counts 无分数字段、9 个官方 key 集合与 `PLANS`
    同源、投递形状客观、verdict 只认本轮响应、`_carries` 必须比较
    解码值(AST)、`_git_head` 不得静默 unknown、MD/JSON 逐字节同源、
    bonus CLI 只是事实。变异 `dev/phase381_mutations.py` **11/11**
    (每个变异只跑一个具名 node),源码/产物字节已还原。
  - **边界**:7 个不是 7 个独立靶、更不是 7 个可比用例;不与 XSSMaze
    1013 例 / 194 矩阵 / Phase 379 的 5 面 / Phase 380 的跨工具表并列,
    不改变唯一官方跑分口径。靶场被本轮写入 3 个 throwaway 用户、
    2 条 feedback 与 lastLoginIp,产品 1 的 `description` 已恢复;
    `dev/_*` 不进版本库。验收(本轮自己的运行):守卫 9 passed / 0 skip、
    变异 11/11、回归组(含 Phase 380 守卫)**39 passed / 0 skip**、
    ruff 全仓零基线。**四档 strict gate 与全量分批门禁本轮未跑**
    (判定面零改动;上轮 quick 补跑挂起仍记为未验证),不拿旧数字顶账。
- **验收(本轮自己的运行,引用带跳过数)**:四档 strict gate 全 exit 0——
  quick 64 sync **0 SKIP**、quick 64 async **1 SKIP**、full 194 sync
  **0 SKIP**、full 194 async **12 SKIP**,全部 FP0/FN0/ERROR0;官方 XSSMaze
  1013 例(旧 GET-only 口径)**TP 975 / FN 38 / FP 0,P 100% / R 96.2% /
  F1 0.981**,1959.1s,27 controls 零误报;POST-aware 新口径 TP 987 / FN 26 /
  F1 0.987(2039.6s),**两口径不可比**且不代表能力提升;五靶场 50 例 sync
  TP31/FP0/TN19/FN0、5 门 exit 0,OOB 回连 e2e 成立(`blind/high/oob-confirmed`);
  ruff 全仓零基线,架构/Mixin/层注册/覆盖矩阵守卫全绿。产物
  `benchmark/results/xssmaze_full_20261108.{json,md}`、
  `xssmaze_full_post_aware_20261108.{json,md}`、`gate_p364_*`、
  `redirect_scheme_fix_and_xssmaze_full_20261108.md`。
- **外部效度清单** `benchmark/results/external_validity_20261108.md`:
  强证据=官方靶+官方答案键+官方评分器;194 矩阵/range/bWAPP 属自证;
  商业工具(Burp/Acunetix/Netsparker)、真实授权目标**零对跑**,ZAP 永久
  `unavailable`,性能仍比 nuclei 慢一个量级。**三个时点(10-24 / 10-30 /
  11-08)不可连成进步曲线**:代码树、wrapper 超时、loopback 状态都不同;
  自证矩阵 F1=1.0 不得与 XSSMaze 并列展示为「两个满分」。
- **已定(2026-11-08,保守默认)**:POST-aware **不**定为新官方口径,GET-only
  仍是唯一官方口径(F1 0.981 那套);POST-aware 只作 opt-in 诊断口径,
  历史数字一律不改、不制造口径断点。理由:切换需重跑全部历史跑分或标注断点
  (`external_validity_20261108.md` §7 第 4 条),而当前收益只是补齐测量盲区。
  将来要切换须显式决定并整体重跑,不靠单轮数字改口径。
- **开放项(需拍板,不擅自做)**:① `docs/OPTIMIZATION.md` §8.1-1 授权范围默认策略
  (默认拒绝 vs 默认放行)——§8.5 明确「拍板前不要动这一条」,**仍未动**;
  #2 / #3 / #5 / #6 已按建议顺序完成,#4 的 ①② 于 Phase 376 完成(见上条),
  **#4 三子项(376/377)与 #7(378)均已完成 ⇒ P1 已清空**,下一步是
  **评估 8–11**;P0 仅剩 **#1 授权范围默认策略**,仍未拍板、继续不动。
  ② PyPI Trusted Publisher 未配。**环境阻塞**:2026-11-08 傍晚起本机
  `wsl.exe` 被安全策略拦,Docker Desktop 后端起不来,XSSMaze 复测当前无法进行;
  同晚 loopback 劣化还造成 `test_phase327` 超时用例的环境形态红(见上条 A/B)。
- 下一节起为**带日期的历史状态记录**,保留不改;「当前状态」以本节为准。

## 历史状态(2026-11-06 及更早,带日期记录保留不改)

> 本节全部为带日期的历史记录(门禁、CI、规模快照、开放项),按规矩保留不改,
> 不以现在时引用。最新状态见上一节。

- **1.4.2(2026-11-06,patch)**:承接 Phase 358–362(MCP 双协议、CLI 管道
  与功能面收口、XSSMaze 残余 FN 归因与三修),无破坏性变更(唯一行为变化是
  `--config` 带默认值的键现在生效,CHANGELOG Changed 已明示),按「只修缺陷/
  补齐既有能力走 patch」定级。版本同源仍由
  `test_doc_gate_parity.py::test_changelog_latest_version_matches_package_version`
  钉住(`__version__` == CHANGELOG 最新章节号)。`pyproject.toml` 用 attr 动态读
  `__version__`,无需单独改。
- 版本 1.4.2;最新 Phase 362。源码 135 文件 60,440 行 / 测试 275 文件 62,544 行
  (2026-11-04 复测)。Phase 350(`757e58f`)已提交;351–356 已随 1.4.0
  (`bad66b2`)发布,过程记录在 `benchmark/results/round2..round5_*_20261103.md`
  与 `zap_unavailable_20261103.md`;Phase 357 为 2026-11-04 的收口轮
  (`f80af43`),本文件只留结论。门禁体系不变:Phase 347 四门禁 + Phase 348
  并行档(`--jobs 4`),机制见 `docs/ARCHITECTURE.md`。
- 口径复测(2026-11-04 晚间,含本轮 3 个 CI/文档守卫与 1.4.1 版本同源守卫):
  源码 **135 文件 60,440 行**不变;测试按 tracked `test_*.py` 物理行为
  **278 文件 62,926 行**。上一行 275 / 62,544 是当日早间的带日期记录,
  保留不改,引用时以本行为准。口径说明:
  未跟踪的 `tests/_pytest_tmp/` 等临时脚本不计入(若按全 `*.py` 会是 317 文件),
  源码侧与本行同为 `wc -l` 物理行。这类规模快照与切片/矩阵常量不同,不设守卫
  (自指守卫会让「加一个测试文件」反过来要求改文档),改动时按本行口径重测。
- 口径复测(2026-11-05 晚间,含 Phase 358 MCP 与 Phase 359 CLI 两个守卫):
  源码 **135 文件 60,797 行**;测试按 tracked `test_*.py`(含本轮新增
  `test_phase358_mcp_dual_era.py`、`test_phase359_cli_compat.py`)
  **280 文件 63,447 行**。带日期的历史记录,保留不改。
- 口径复测(2026-11-05 深夜,含 Phase 360 的 `cli_output.py` 与
  `test_phase360_cli_compat.py`):源码 **136 文件 61,042 行**;测试按同口径
  (tracked + 本轮待提交的 `test_phase359_cli_compat.py`、
  `test_phase360_cli_compat.py`)**281 文件 63,869 行**。带日期的历史记录,
  保留不改;口径仍是 `wc -l` 物理行、排除 `__pycache__` / `tests/_pytest_tmp/`。
- 口径复测(2026-11-06,含功能面审计的 `test_phase360_cli_surface.py` 与
  `core/llm_pool.py`、`core/checkpoint.py` 的修法):源码 **136 文件 61,138 行**;
  测试按同口径 **282 文件 64,173 行**。**引用以本行为准**。
- 1.4.0 轮落地的能力(Phase 351–356,全部带回归,数字与归因见上列报告):
  - **Phase 352** 存储自动发现独立 Mixin(`scanner_stored_auto.py` +
    `stored_discovery.py`),官方靶 stored 自动发现 sync 9/9、async 9/9、FP 0;
    `--stored-auto` 为 sync 默认(显式 `--stored-inject` 时让位);行数走
    「拆新 Mixin」不走抬预算;死目标上熔断器正确早停(2026-11-04 门禁日志实测)。
  - **Phase 354** DOM 静态层精度收敛:AST 优先(esprima 跨语句污点链)、正则
    兜底;5 类真实框架写法(title/aria-label/.attr('title')/.val/appendChild)
    不再报 medium,真 sink(innerHTML/document.write/attr('href')/
    setAttribute('onclick'))保留;DVWA guestbook 页实测 120 low /
    0 medium-high,low 一律不进告警。边界明示不假装解决:计算属性名、跨语句
    对象身份、外部 bundle(归浏览器臂)。守卫:`tests/test_dom_static_precision.py`、
    `tests/test_dom_source_gate.py`。
  - **Phase 355** 认证会话下 header canary 排除 Cookie(`transport_layers.py`);
    `tests/test_phase355_transport_canary.py` 14 例。
  - **Phase 356** marker forms:同一注入点先按引号形态 fan-out,一发 plain 探针
    命中即返回(addslashes 杀单引号形态,杀不了裸/双引号/反引号);unquoted
    形态用 sha1 派生的 10 位数字别名(`verifier.numeric_alias`),stored 路径
    每个 (form, transform) 对发新 token。守卫:`tests/test_phase356_marker_forms.py`。
- **Phase 357(收口轮,`f80af43`)** 同一族问题又出现两次:「同一契约被手写两遍」
  与「判定依赖页面特征而非原始字节」:
  - async 仍用 `verifier.mark(payload, marker)` 单形态并以 base marker 验证,
    sync 的引号形态 fan-out 没过去 ⇒ bWAPP medium(PHP `addslashes`)的
    reflected/header 24 组全是 FN。补齐 `_detect_quote_escaping_async`(每参数
    一次探针)、主形态保留载荷自身的 alert 参数风格、extra 形态作为
    `marker:<form>` plain 变体、**每个变体用自己的 effective token** 验证
    (numeric 形态是 10 位别名)。健康目标 budget 仍为 1,请求数不变。
  - CI run `41699972311` 唯一红 `test_phase356_marker_forms.py`:
    `<svg%00/onload=…>` 在 linux libxml2 里保留为带 handler 的元素、Windows
    wheel 丢整个标签 ⇒ 依赖解析树的结构规则给出跨平台相反结论。
    `verifier._token_in_mangled_tag_head` 改在**原始源码**上、且**先于**
    BeautifulSoup 解析判定,只看 tag name(属性里的 `%00` 不算)。
  - 守卫 `tests/test_phase357_async_marker_parity.py`(22 例):AST 钉住双引擎
    调用点(共用 helper / effective token / budget / concat 闸门 / raw-source
    检查位置)、真实 `_probe_param` 行为、A/B 开关、numeric replay token;
    变异对照 baseline 绿 → 改回 base marker + 关闭 helper 红 3 例 →
    restored 绿;numeric 规则另做一次变异(`\d{10}`→`\d{11}`)红 2 例。
  - **本轮首次推送 CI run `41799682389`:tests job 绿,drills 的 Range #3 红**
    (上次 `41699972311` 的 drills 是 success ⇒ 真回归,非环境抖动)。
    async 主形态改成 `alert(<10 位别名>)` 后,
    `findings.extract_replay_token` 只认引号 token / `xss` 前缀 token,
    取不到别名 ⇒ `_headless_verify_finding` 以「不可归属复验」整段跳过,
    range3 唯一的 `fired` 行消失(本地复现 TP17/FP0/TN7/FN0 但
    `confirmed=0`)。修法:共享契约补 numeric 形态
    `(?:alert|confirm|prompt)\(\d{10}\)`(只认 10 位,`alert(999)` 不算),
    sync/async 两侧同时受益;本地 Range3 gate exit 0,async fired 11/11。
    **教训:新增 marker 形态时,凡是「从 payload 反推 token」的消费者都要
    一起过一遍**——Phase 356 补了 stored 成本守卫与浏览器对话通道,漏了
    headless replay 提取器,这一课与「同一契约手写两遍」同族。
  - 证据:全量 **194 例** strict 门双引擎 exit 0(sync 113/0/81/0、0 SKIP、
    389.7s;async 107/0/75/0、12 SKIP、394.1s;产物
    `benchmark/results/benchmark_full_{sync,async}_20261104.json`);quick 64
    双引擎 F1=1.0、27 控制例 0 FP;bWAPP 72 组矩阵修前/修后
    (`bwapp_matrix_pre_fix_20261103.md`)medium 24 FN→TP、high 24 TN 不变;
    关联测试 60 passed。manifest 现为 **194 例**,旧记录的「192 例全量」是
    历史口径,引用时以本次产物为准。修复 headless replay 后按同规矩再跑一次
    全量 194 双引擎(产物 `benchmark_full_{sync,async}_20261104_r2.json`):
    381.6s / 388.9s,TP/FP/TN/FN 与上一轮完全一致、exit 0;
    Range3 本地 gate exit 0(async r3-pos-utf7 fired 11/11)。
- **Phase 358(MCP 双协议接入,2026-11-05)** 起点是「被智能体 MCP/CLI 链接」
  的兼容性:现行规范 `2026-07-28` 已去掉 `initialize` 握手、把版本放进每请求
  `params._meta`、强制 `server/discover`,而服务只认到 `2025-06-18`;实测
  `server/discover` 回 `-32601`,声明 `1900-01-01` 也照常应答。另一处是
  Windows cp936 下 `ensure_ascii=False` 写文本 stdout,遇靶场中文/emoji
  直接 `UnicodeEncodeError` ⇒ 帧丢失、客户端永远等不到响应。
  - 改法:**dual-era**,按请求是否声明现代版本自动分代。legacy 帧的响应字节
    与 HTTP 状态码一律不变;现代帧带 `resultType` / `_meta.serverInfo` /
    `ttlMs` / `cacheScope`,未知版本回 `-32022` 附 `supported` 列表(不再静默
    降级)。HTTP 头/体不一致 `400 -32020`、未知现代方法 `404 -32601`,
    缺头放行(兼容实现不完整的 CLI)。stdio 改 UTF-8 字节通道:有 buffer 走
    字节写、stdin 按 UTF-8 解码,注入的文本流保留 ASCII 转义兜底。
  - 守卫 `tests/test_phase358_mcp_dual_era.py`(21 例):新旧两套帧、真实
    子进程 stdio 握手、cp936 读写、HTTP 状态码;4 组变异对照
    (去掉 discover / 回退旧 `_write` / 改错误码 / 回退文本 stdin)各自红、
    restored 全绿。
  - 证据:相关测试组 25 文件 **343 passed / 0 skip**;ruff 全绿;既有 MCP
    88 例在改动前后全绿(legacy 契约未破);文档/架构守卫 24 passed。
  - 全量分批门禁(2026-11-05,本机劣化期):`--jobs 4` 两轮分别
    **252/279 与 247/279 文件 in-gate 绿**,exit 27 / 32,
    **12 skip / 5 文件**(2 个整文件零贡献)。红文件 stdout 全是
    `100%` 断言通过,唯一失败原因是本 agent turn 的
    `[safe-delete]` 50 次删除/覆盖配额被 pytest 临时目录清理
    (`.lock` / `garbage-*` )吃光,属环境形态、不是回归;
    32 个红文件按劣化期协议分 4 组单跑全绿
    (**504 passed / 1 skipped**)。引用时两组数一起报。
  - **明确不做**:2026 规范的 MRTR、`subscriptions/listen`、SSE 流属于新能力,
    本轮只解决「连得上」,不引入新传输。
  - 教训:协议代际与控制台编码都是「接得上」的前置条件;跑分/判定全绿不代表
    Agent 能连上,接入面必须有真实子进程 e2e,而不只是注入流单测。
- **Phase 359(CLI 管道兼容,2026-11-05)** 以真实 CLI 子进程对照测出的五个硬缺口:
  ① `--batch` / `--batch-stdin` 带 UTF-8 BOM 时首行 `\ufeff# c` 被当 URL
  (`Invalid URL` rc=2);② GBK 列表抛未捕获 `UnicodeDecodeError`(rc=1 +
  traceback);③ `-o -` 被当文件名写出 `-.json`,stdout 只有人类摘要;
  ④ `-o reports/scan.json` 父目录不存在时写失败并误报 exit 3;
  ⑤ 无目标时把 40KB `--help` 打到 stdout、错误却在 stderr。
  - 修法:输入侧按 UTF-8-sig → UTF-16(BOM) → GB18030 解码、CRLF/BOM/注释统一
    清洗,无法解码给诚实错误;输出侧 `-o -` 为 UTF-8 字节 stdout 通道(单目标
    一行 JSON,批处理 JSONL 且限 `-f json`),人类摘要/进度/错误全部改走
    `_human` 流,自动创建父目录;用法错误只回 stderr 短提示。退出码
    `0/1/2/3` 语义不变,由测试钉住。
  - 守卫 `tests/test_phase359_cli_compat.py`(13 例):真实 CLI 子进程 +
    loopback 靶场、注入流的解码单测、**AST 断言 `_main_impl` 内所有 print
    都显式指定流**(防未来新增 print 污染 stdout);5 组变异对照各自红、
    restored 全绿。
  - 证据:CLI/报告相关 13 文件 **158 passed / 0 skip**;文档/架构/MCP 守卫
    6 文件 **65 passed**;ruff 全绿;既有 MCP/CLI 契约未破。
  - 教训:「管道公民」和「终端程序」是两套输出契约;只修输出通道不够,
    必须把人类文本统一到 stderr,并用源码级断言锁住新增打印点。
- **Phase 360(CLI 兼容性收口,2026-11-05 深夜)** 起点是一轮**真实子进程
  探针矩阵**(`dev/cli_compat_probe.py`,修前/修后 JSON 留证),不凭代码观感
  列清单。量出的六组硬缺口:
  ① `--version` / `-V` 不存在(rc=2 + 5.6KB usage 到 stderr);
  ② **Phase 359 的 AST 门只钉 `_main_impl`**,`__main__` / `cli_runner` /
  `cli_commands` 另有 **97 处裸 print**,实测 `-o -` 下 `--login-token` /
  `--login-basic` / `--ai-report` / `--fuzz` / `--discover` / `--har` 导入
  都把人类行写进报告流;
  ③ `--config` 带 UTF-8 BOM 被静默吞成**空配置**(报「No target specified」
  把文件问题栽给使用者),GBK 配置 rc=1 + traceback;另外凡带非空 argparse
  默认值的键(`format` / `timeout` / `output` / `method`)写了也不生效;
  ④ `-o - -f nuclei` 单目标扫完才在报告写入处抛 ValueError,被当成
  「Report write failed」→ exit 3,而批处理同错是 exit 2;
  ⑤ `-o - | head` 把剩余每个目标标 failed、exit 3,退出时还留
  `Exception ignored on flushing sys.stdout`(实测 rc=120);
  ⑥ stdout 无 `.buffer`(注入的文本流 / cp936)时非 ASCII 报告丢帧。
  - 改法:新增 `xssentinel/cli_output.py` 收拢两份契约——`human()` 流
    (默认 stdout,`-o -` 时 stderr,`main()` 的 finally 复位,不是全局
    `sys.stdout` patch)与 `decode_input_bytes`(UTF-8-sig / UTF-16 BOM /
    GB18030)。97 处 print 全部显式 `file=human()`;坏配置改抛 `ConfigError`
    → rc=2 明确原因;`_explicit_cli_values()` 用「默认值置 None 的第二遍
    parser」区分显式输入与 argparse 默认值(避免手写默认值清单);
    `--config` 自带 `output: "-"` 时在 merge 之后重新绑定流;`-o -` 的
    nuclei / 批量非 JSON 统一为扫描前 rc=2;`OutputPipeClosed` 从 per-target
    与并行批量的 `except Exception` 里单独冒到 `main()`,rc=0 + 一行说明。
    `--version` 用 `__version__` 同源;`--ver` 作为 `--verbose` 的**同一个
    action 的精确别名**保留(单独注册隐藏 action 会与 `verbose` 共享 dest,
    被 `test_cli_subcommands` 的 dest→action 映射当场抓到)。
  - 守卫 `tests/test_phase360_cli_compat.py`(**34 例 / 0 skip**):真实 CLI
    子进程 + loopback 靶场覆盖 5 类污染、HAR 导入、config 三种编码与四种
    坏形状、配置优先级、config 驱动的 stdout 通道、nuclei 门、BrokenPipe、
    cp936 文本流兜底;源码级 AST 门覆盖**三个 CLI 模块的所有 print**(不再
    只钉一个函数)且禁止硬编码 `file=sys.stdout`。取证脚本
    `dev/phase360_rewrite_prints.py`(AST + 字节偏移改写,CRLF 与非 ASCII
    列偏移两个坑)、`dev/phase360_mutation_check.py`。
  - 变异对照**首次运行 6/6 通过**(版本 / 裸 print / 静默吞配置 / nuclei 门 /
    管道吞异常 / 默认值覆盖,baseline 绿 → 改回旧行为红 → restored 绿)。
    **最终代码上两次重跑,后 4 组未完成**:前 2 组(版本 / 裸 print)每次都
    baseline 绿 → mutated 红 → restored 绿,第 3 组 baseline 两次都被本 turn
    的 `[safe-delete]` 50 次删除/覆盖配额(count 51 > threshold 50,pytest
    临时目录 `garbage-*` 清理吃光,与 Phase 358 记录的环境形态相同)中止。
    ABORT 发生在写 mutated **之前**,源码已核实干净(无 `MUTATED` / `-Vx` 等
    残留),不是回归;配额按 turn 计,下轮环境干净时补跑后 4 组。首轮 6/6 与
    最终代码的唯一差异是 `--ver` 注册方式(同一 action 的精确别名),与 6 个
    变异锚点均无关,但不拿首轮结论冒充最终代码的全量结论。
  - 证据:CLI / MCP / 报告 / 文档 / 架构 13 文件 **115 passed / 1 skipped**
    (唯一的 skip 是 `test_no_undefined_names.py` 因 pyflakes 未安装的**整文件
    零贡献**,按规矩不当绿算);Phase 360 守卫单跑 34 passed / 0 skip;
    文档 / 架构 / 刻度守卫 5 文件 34 passed / 0 skip;ruff 全仓全绿;
    Phase 358 / 359 既有契约未破。按「引用带跳过数」的口径,两组数一起报。
  - **本轮未跑全量分批门禁**(`--jobs 4`):同一 turn 的 safe-delete 配额被
    变异对照与回归组的 pytest 临时目录清理占用(下条),全量跑只会产出
    Phase 358 记录过的环境形态红,而不是判定。按「绿和跑过是两个词」不以
    「跑过」充当「绿」,也不拿旧 run 的数字顶上;下轮环境干净时补跑。
  - **明确不做**:shell completion、`version` 子命令、位置参数形式的目标
    URL、`--config` 的 YAML、禁用 argparse 缩写(会破坏既有脚本)。
  - 教训:与 Phase 357「同一契约被手写两遍」同族,这次是**守卫覆盖面没跟着
    能力面走**——修了 `_main_impl` 的流,却让另外两个模块继续自由打印;
    有效做法是「共享函数 + 全模块源码级门 + 真实子进程行为门」三者同时在场。
    另一课:探针里把 `--version` 改名不算变异(argparse 缩写仍能命中),
    变异必须真正改变行为,否则守卫绿是对的。
- **Phase 360 后续:CLI 功能面审计(2026-11-06)** 追问「CLI 是否都能正常
  调用里面的所有功能」,答案不能凭代码观感给。写了
  `dev/cli_surface_probe.py`:29 个功能面用例(4 个子命令 help、9 个程序
  模式、6 个输入面、8 种报告格式、长驻服务启动检查)+ 从 `build_parser`
  自动枚举的 **133 个 flag**(161 actions / 174 option strings 中排除 31 个
  需外部条件或已单测的,每个都带合理占位值真实跑一次),判定口径是
  「有没有未捕获异常 / traceback」,而不是「feature 是否语义正确」——后者
  由 194 例基准与各功能专属测试负责。
  - 修前实测:**2 处崩溃**(`--raw-request` 坏文件抛 RawRequestError、
    `--resume` 非对象 JSON 抛 AttributeError),1 处功能不可达
    (`--self-test` 的 8899 被本机一个无关的 `python -m http.server` 长期
    占用,三处硬编码同一端口),2 处契约漏接(`--poc-dir` 写失败被算成
    exit 3、`--ai-timeout` 声明了却没传给 `--ai-check`)。另有若干
    **探针 fixture 自身**的形状(fuzz-body 需 `@` 前缀、verify-fix 需非空
    findings、sitemap 需 `--allow-host`、ai-check 需网络超时上限),逐个
    归因后修正探针,不拿它们冒充产品缺陷。
  - 修后同探针复测:**29 功能面 0 崩溃**(24 rc=0、3 个长驻模式 running、
    1 个 verify-fix 的 CI 门 rc=1、1 个 self-test 人为 8s 超时但
    `ready=True`)、**133 flag 0 崩溃 / 0 超时**(129 rc=0,其余是占位值
    导致的诚实用法错误或 CI 门 rc=1)、**8 种报告格式全部产出非空文件**。
  - 守卫 `tests/test_phase360_cli_surface.py`(**26 例 / 0 skip**):
    真实子进程 + 三个文件共享端口的 AST 门 + `--ai-timeout` 转发的
    源码级断言 + fake probe 行为单测。变异对照
    `dev/phase360_surface_mutation.py` **5/5 通过**,且这轮改为**纯子进程
    驱动、不经过 pytest**,避开上一轮把 safe-delete 配额吃光的临时目录清理。
  - 证据:CLI / MCP / PoC / LLM / Checkpoint / 文档 / 架构 21 文件
    **247 passed / 0 skipped / 0 failed**(337s);ruff 全仓全绿。
    **仍未跑全量分批门禁**,理由同上一条(本轮同样用 pytest 临时目录,
    配额按 turn 计),下轮补跑。
  - 边界(如实说):审计覆盖的是**入口可达性**,不是 2^161 种参数组合的
    语义正确性;`--wayback` / `--gql` / `--headless` / `--webhook` / OOB
    监听等需外部服务或浏览器的 flag 未逐个实测,由各自专属测试覆盖;
    `--serve` / `--passive` / `--mcp` 只验证「能启动并留在前台」。
  - 2026-11-06 收口:`--diff` / `--verify-fix` 自己拼报告时同样把 `-` 当
    文件名(`-.json` / `-.html`),现与扫描入口共用
    `cli_output.write_report_frame`;回归测试在临时 CWD 断言不出现
    `-` / `-.json` / `-.csv`(扫描与 diff 两个入口)。根目录历史残留
    `-.json`(14,748B)/`-.csv`(518B,2026-11-05 23:11)已删除。
- **Phase 361–362(XSSMaze 残余 FN 归因 + 三修,2026-11-06)** 回答「检测
  功能还能不能提升」这个问题时,先做了 Phase 361 归因:不重跑全靶,用
  `dev/_xssmaze/fn_delta_p310_p341.py` 从两轮原始 TSV 重推差集(方法自校验:
  p341 重推 = 69 整,与官方 scorecard 一致;「最新目录不是我的目录」在这一步
  直接兑现为「最新归因报告归因的是旧一轮」——10-25 的
  `FN_ATTRIBUTION_20261025.md` 归因的是 p310 的 81 FN,Phase 315–322 修复波
  关闭 16 个后,当前 69 的残余归因没人做过)。归因结论(全部有实测证据,
  报告 `dev/_xssmaze/FN_ATTRIBUTION_20261106.md`):69 = 4 预算挤占 + 4 path
  产品缺口 + 31 合同结构性(body 25 + header 6,dalfox 与 nuclei 在同一
  URL-only 合同下同样全 0,不归检测逻辑)+ 28 真实 query 缺口 + 2 超时形态。
  三个「新 FN」逐一验明:2 个是 p341 轮 wrapper 100s 超时的环境形态(当前树
  1.3s 复验 TP),1 个(eventhandler/level3)是真回归。
  - Phase 362 三修(全部靶场活体验证,默认预算):
    ① `build_test_url` 首次**子串**替换改**整段**替换(核心 `path_xss.py`)——
    官方靶 `/path/level1/a` 的第一个 `a` 在目录名 `path` 里,探测从未碰过终端
    段(`docstring` 把 bug 写成了契约);dalfox 3/4、nuclei 4/4 同合同可检出,
    修后 4/4 `path_xss` medium;
    ② verifier event-handler 确认位点加 **UTF-7 charset 门**——mp40 轮的
    「确认 high」实为 oracle 伪影(页面无 UTF-7 charset 声明,浏览器不会解码,
    扫描器自己的 `poc_verify` 都拒了同一 finding,`not_reproduced`);
    range3 真 UTF-7 页声明 `charset=UTF-7`(server.py:192),诚实案例不受影响;
    ③ bracket-dead 队列注入——画像显示 `<` 被剥时,语料新增的三条
    `attr_name_injection` 裸形状(`ondblclick` / `onauxclick` /
    `marquee onstart`)进默认预算窗口(sync `_prioritize_bases` 与 async
    同型点接线,Phase 357 双引擎教训)。eventhandler/3、4 以
    `ondblclick=alert('xssv_...')` 诚实确认 high,level5 以
    `marquee onstart=alert(...)` 确认(level5 连裸 handler 名也剥,括号被剥
    后 `onstart=...` 才是真属性),realworld-encoding/8 确认 high。
    净变化:**+8 诚实 TP**(p341 基线上全 FN),27/27 控制例 FP=0。
  - 自纠正四笔(都钉在测试与报告里):① 队列顺序——「裸形状最先」的直觉
    排列把 level5 的语料 polyglot 条目挤出 14 窗口(其早前 medium 是不可
    复现的队列巧合,40 预算主循环 0 确认),落定为 lab 实测 8/8 的排列
    (注入在 generative prepend 之前);② 守卫空转——`if False and` 变异
    从源码子串钉子上滑了过去(Phase 201 续四形状),sync 接线改**行为测试**
    (monkeypatch 画像探针驱动真 `_prioritize_bases`)+ 精确语句钉子,
    三个锚点全部 baseline 绿 → mutated 红 → restored 绿;③ **bracket_dead
    两道前置**——首轮全量门禁抓到 5 个真回归后归因:`profile_reflection`
    对「探针未被回显」返回 `chars_kept: []`,第一版据此把「过滤未知」误判
    为 bracket-dead,裸形状占满 Phase 315 async HPP 的 `cands[:2]` 重发位、
    hpp finding 消失;escaped 页的 `<` 走**编码**(Phase 311 夹具),同样不在
    kept,3 条裸形状吃光其 3 槽预算。落定:探针必须回显(`reflected`)且
    `<` 必须在 `chars_stripped`(编码≠被剥);④ HPP 层 outright 跳过
    `attr_name_injection` 形状(双引擎)——两种 HPP 排序位置都无法把
    裸形状变成活属性,重发位只该花在能确认的形状上。
  - 守卫 `tests/test_phase362_xssmaze_fixes.py`(22 例):build_test_url
    精确等值锚(排除 append 分支侥幸)、UTF-7 门三态(header/meta/无依据)+
    helper 直测 + 双位点源码钉、bracket_dead 三态单测(被剥/未回显/被编码)、
    语料形状、双引擎接线。`test_portswigger_events_corpus` 常量按其自带
    协议抬 209→212(附日期与矩阵复测依据);语料 3 条移至 html_element
    家族尾部(stride 位移最小化)。ruff 全绿;架构行数门绿。
  - **第一轮全量门禁的战果**:exit 0 但 per-file 日志带 5 个红
    (ratchet×2、portswigger 契约、Phase 315 async HPP、Phase 311
    escaped-echo)——单文件复跑定性全部为真回归(非环境形态),即上面
    ③④ 的来源;修后同组 75 例全绿。教训:exit 0 不等于可以只引总数,
    失败/重试日志才是证据来源。
  - **终树门禁(2026-11-06,本节引用口径)**:全量分批门禁 `--jobs 4`
    **283/283 文件绿(956s,失败 0)**,skip **37 例 / 13 文件**(2 个
    整文件零贡献),2 个文件首跑超时重试后复绿(test_phase209_
    accept_encoding / spa_route_delivery);194 矩阵双引擎(14/12/90
    标定口径)sync **TP113/FP0/TN81/FN0/ERR0**(524s)、async
    **TP107/FP0/TN75/FN0/ERR0**(537s;12 SKIP 为 manifest 声明
    sync-only 的 `neg-stored-02` 口径),双双与改前基线逐位一致,F1 均
    1.000,产物 `benchmark/results/phase362_matrix_{sync,async}_r2.json`
    (r1 为修 5 回归前的树,数字同,留档)。测试规模口径随之 +1 文件
    (283 含本轮 `tests/test_phase362_xssmaze_fixes.py`)。
- 真实应用回归集 v2.2(22 例 / 5 app:Juice Shop 匿名+unsafe、DVWA、bWAPP、
  自建四面靶):xssentinel **13 TP / 0 FP / 9 TN,recall 1.000**;dalfox 0.571、
  nuclei 0.500(开源对照,3 FN 均为 Juice `#` fragment 形状;**非商业基线**)。
  bWAPP 双角色三面(官方 `bugs.txt` 对齐);多角色:DVWA 三档矩阵、Juice
  customer→deluxe 走官方 `freeDeluxeChallenge` 路由(合法可达;accounting 该
  版本不存在)。结论已定不再投入:Juice 持久化反馈(服务端 `sanitize-html`
  入库即剥离,18 载体 0 可执行)、ZAP(环境不可达,永久 `unavailable`)、
  XVWA(镜像源 not found,一次放弃)、async 提速(洁净复测 19.2s vs 15.9s
  = 1.21×,≤2× 达标不动代码;旧 101.1s/7× 为受污染测量,不混算)。
- 成熟度:`pyproject.toml` 降 **Beta**(理由注释在文件内);README 增
  「已具备/尚未具备/适用边界」实测口径声明。
- **门禁拦下的三件事(2026-11-04 全量门禁与单文件复跑实测)**:
  ① `test_architecture_scale.py`:scanner.py 2438>2400、scanner_stored.py
  1107>1100。按预算表自身约定(ceiling = 实测 + ~10%,历史校验
  2400/2246=+6.9%、1100/982=+12%)抬至 **2650 / 1200**,理由钉在 BUDGETS
  注释:marker-form fan-out 在 `_try_payload` 内部,方法的一半搬不走;
  `_detect_quote_escaping` 与 `_probe_reflection_profile` 同族同文件——拆半
  方法=改写本轮新逻辑,违反「搬代码与改逻辑绝不混在同一轮」。
  ② `test_layer_registry_parity.py` + `test_coverage_matrix_parity.py`:
  Phase 356 新层 `L1_marker_forms` 只注册了 `coverage.LAYERS`,漏了
  `benchmark/layer_coverage.py` 矩阵——Phase 187/192 同一课第三次触发,两处
  已同时注册。
  ③ `test_stored_matrix_cost.py`:stored 路径开始提交 numeric 别名形态
  (`alert(4856344953)`,无 `xssv_` 前缀)。核实该形态**可确认**——别名就是
  `stamp_form` 记录的 effective token,`verify_semantic` 子串匹配、浏览器臂
  对话通道(dom_engine Phase 226)都按数字匹配;是守卫的 `xssv_` 正则比新
  行为窄。守卫改为认「`xssv_` token 或 10 位数字别名」两种可确认形态,对
  mangled token 的牙齿不变(被改坏变体不会凭空出现 10 位数字串);总成本
  仍由同文件 ≤520 预算测试钉住。
- benchmark strict 64 例切片双引擎 F1=1.0(async 的 1 个 SKIP 是 manifest
  声明 sync-only 的 `neg-stored-02`);27 控制例双引擎 0/27 FP。
- 最近全量分批门禁(2026-11-04 凌晨,本树,`--jobs 4`;当晚机器持续抖动,
  四轮中以此轮为引用口径):**271/274 文件 in-gate 绿,exit 3**,1412s;
  **skip 69 个 / 18 文件**(5 个整文件零贡献)。3 红全是环境形态(TIMEOUT×2
  撞 per-file 1080s 预算 + fixture ReadTimeout),单文件复跑全绿且快:
  `test_phase196_csp_delivery` 21 passed/10.3s、`test_phase193` 10
  passed/17.9s、`test_sitemap_input` 9 passed/11.6s。合计 **274/274 文件绿**
  (271 in-gate + 3 单跑),引用时两组数一起报。前一轮 272/274 受 vuln-agent
  并发污染不引用;另有一轮 runner 本体无总结退出(exit 1、无 _timings,
  stderr 未捕获,当晚仅一次)。与 2026-11-02 的 268 文件/620s/13 skip
  **不是同一机器状态**,不作商引用。
- CI(`.github/workflows/ci.yml`):7 个 job(6 个 ubuntu-latest +
  `windows-smoke` 走 windows-latest)—— tests(全量分批 + ruff)、drills(双引擎
  strict 切片周轮转 + range2–6 门禁;range7 走 tests job 的 pytest 契约测试)、
  min-python(3.10)、benchmark-full、nightly-gate、dependency-audit、
  windows-smoke;push 门 = 双引擎 strict 切片。2026-11-04 起全量分批门每次 run
  只跑一次:`tests`(push/PR,60min ceiling)或 `nightly-gate`(schedule/dispatch,
  150min ceiling),事件条件互补由 `tests/test_ci_no_duplicate_gate.py` 钉住
  (此前 schedule run 会把同一入口跑两遍,CI #18 实测 45m36s + 29m38s)。
  `tests` 的安装面按同一组事件分流:push/PR 装全套,schedule/dispatch 只装
  `.[dev]` 跑 ruff(CI #29 实测原为 56s job 里 50s 安装),由同一守卫钉住。
- **本轮 CI 复验**:`41799682389`(`f80af43`)tests 绿、drills 的 Range #3 红
  (归因见 Phase 357 段);修复 `906ed11` 后 `41809643713` **整体 success**
  (tests / drills / windows-smoke / min-python 全绿,其余按设计 skipped)。
- **1.4.1 轮 CI 证据(2026-11-04 晚间,只记已定论的 run)**:`41809643713`
  之后的 push 链 #24 `41813166800`(`156561b`)、#25 `41816092611`(`e4b6f31`)、
  #26 `41817487077`(`dc5ad1f`)、#28 `41819901219`(`9e62ba2`)、
  #30 `41830007477`(`d5a69e2`)全部 **success**;手动 dispatch
  #29 `41820071633`(`9e62ba2`)**整体 success、7 个 job 全绿**
  —— `nightly-gate` 的全量文件门禁 + evidence-shape sweep、
  `dependency-audit`(setuptools 升级后 `No known vulnerabilities found`)、
  `drills`、`benchmark-full` 全 194 例,以及 `tests` 的 ruff;这是方案①
  「每次 run 只跑一次全量门禁」与审计修复的闭环证据。#27 `41817920644`
  的 failure 已定性为修前 runner setuptools 告警,由 `9e62ba2` 修复并在
  #29 复验绿;  #31 `41830062679` 是误触发的重复 dispatch run,已 cancelled。
  补记(21:14 复查):#32 `41830070682`(`d5a69e2`,dispatch)与 #33
  `41832221185`(`9b9ff2f`,push)随后均 **整体 success**;#32 的
  `nightly-gate` 全量门禁 + evidence-shape sweep、`benchmark-full` 全 194 例、
  `dependency-audit` 全绿,`tests` 的 `Install (lint only)` 9s,是安装面
  拆分的闭环证据。
  本行不写「进行中」的 run(会立刻腐烂),引用门禁结论一律以 run 页面为准。
- 开放项:无。SECURITY.md 的举报渠道已定为 **GitHub 私密安全通告**(仓库 → Security →
  Report a vulnerability,流程与 72 小时时效已写在 SECURITY.md,无需额外邮箱即可生效);
  原「联系方式待仓库归属者填写」一项于 2026-11-01 关闭。如需增加邮箱等第三方渠道,
  由仓库归属者自行补充,不阻塞发布。既有 backlog 无未决项
  (OPTIMIZATION.md §3.6 item 6 被动代理 drain 时间上限已于 2026-10-31 关闭;
  其余均为"有意不做/需外部条件"清单)。
- **新增开放项(2026-11-06,仅评估、未实现)**:OPTIMIZATION.md §8「Agent
  接入面 backlog」,11 项按 P0/P1/P2 排序,来自 `dev/agent_surface_probe.py`
  的真实 MCP 帧测量(产物 `dev/_agent_surface_probe.json`)。P0 三件:授权范围
  缺服务端强制、错误结果只有纯文本无结构化、200 finding 静默截断;
  P1 四件:默认 `max_seconds=300` 与 Agent 平台超时错位且无异步入口、7 个工具
  全无 `title`/`annotations`、进度通知无 `total`、重试不幂等。**其中授权范围
  的默认策略(默认拒绝 vs 默认放行)需仓库归属者拍板,拍板前不动。**
- 环境事件(2026-11-04 凌晨):① 邻项目 `D:\qoder\vuln-agent` 同时段并发
  跑自己的测试批(污染一轮门禁,该轮不引用);② 负载抖动贯穿夜间——同一
  文件单跑 2.2s~176s、门禁内可 1080s×2 超时,skip 数 59→69→134 随 conftest
  探针摆动,失败一律按劣化期协议单文件复跑定论、不当回归(`test_batch_input`
  拒连红即此形态,复跑 5.4s 全绿);③ 出现一个外部迷你 runner(00:45 /
  02:23 两次,各 1s,只跑 `test_quick_gate_slice` + `test_doc_code_counts`,
  0 失败,来源未确认,疑似另一个会话的观察进程);④ runner 本体一次无总结
  退出(exit 1,见上条);⑤ `benchmark/server.py` 二度被外部进程删除后恢复,
  来源仍未确认,再现时用 `git show HEAD:benchmark/server.py` 恢复;
  ⑥ 2026-11-04 16:09 该文件第三次被删(关联测试收集期报
  `OSError [Errno 9] Bad file descriptor`)。恢复用
  `git cat-file blob HEAD:benchmark/server.py` 或
  `git checkout -- benchmark/server.py`;注意 `core.autocrlf=true`,直接
  `git show HEAD:... > file` 落 LF 会产生 2704 行整文件级假 diff,
  只有 `git checkout --` 会还原工作区应为的 CRLF。

## 环境配置

- 本机装依赖走 **uv**(`uv pip install --python .venv/Scripts/python.exe ...`):
  2026-10-31 实测 pip 通路病态(TLS 已建立但近零吞吐,2MB 自升级 15min /
  461s CPU 空转,同址 curl 1s 可达;直连与清华镜像同病),uv 10s 完成。
  venv 建法照旧 `py -3.12 -m venv .venv`(默认 `python` 是 3.9,项目已弃)。

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(裸跑单进程会卡死,
  必须分批;runner 对个别慢文件带 per-file 超时 override,失败/重试才写日志)。
  **日常全量门禁加 `--jobs 4`**:2026-11-02 实测 268 文件 616s(顺序档 1 保留为默认,
  两档逐文件 verdict 一致;并发只换墙钟,不改判定)。
  2026-10-31 实测 258 个 test_*.py 文件 / 59289 行;本机 loopback 劣化期的失败先单文件复跑,
  按「未验证」记账而不是当回归(2026-10-05 实测形态,归档 Phase 201 有完整归因)。

- benchmark: benchmark/ 目录;报告产物: report.html;strict 切片产物在 `benchmark/results/`。

- 三方对照(dalfox / nuclei)本机可跑:`go install github.com/hahwul/dalfox/v2@latest`
  经 goproxy.cn 构建到 `$GOPATH/bin`(本机为 `C:\GoWorkspace\bin`),nuclei v3.9.0 与
  `~/nuclei-templates/dast` 已在位;github.com 的 release 资产下载仍被拦(v3 Rust 版装不上)。
  跑法见 README「同类开源扫描器同靶跑分」一节;产物 `benchmark/results/phase196_cross_tool.json`。

- 本机 Windows 侧环境事实:端口走 **18xxx 段**(Windows 保留段 8810-9109 教训,Phase 179);
  测试 fixture 用 port 0;loopback 健康度由 `tests/conftest.py` 的 socketpair/loopback 探针
  决定(可用 `XSSENTINEL_FORCE_SOCKETPAIR=bad|good` 强制),劣化时测试按门禁跳过而非假绿。

- **完整性标签(Phase 346 实测)**:本工作区树带 **Low 强制完整性标签**
  (`icacls` 见 `Mandatory Label\Low Mandatory Level`,`.venv` 与其中全部 `.exe` 同),
  Windows 会把它传给子进程 —— **Low 进程写不进 Medium 的 `%TEMP%`**。三解释器对照:
  树外 `python.exe` = HIGH 可写;同一 exe 复制进树 = LOW 拒写;同副本
  `icacls /setintegritylevel Medium` = 可写。后果是 Playwright 的
  `tempfile.mkdtemp()` 全挂(真浏览器测试必红)。
  `tests/conftest.py` 因此装了**可写 TEMP 回退**(仅在 `%TEMP%` 真不可写时启用,
  落到 `tests/_pytest_tmp/`,已 ignore)。
  **探针有两个陷阱,都实测过**:`os.access(W_OK)` 答 ACL、看不见标签;
  `tempfile.gettempdir()` 不是 `%TEMP%`(Python 自己回退到 CWD,而 node driver 直接读
  `TEMP` 环境变量)。改这块前先读 `tests/test_temp_probe_contract.py` 的 docstring。
