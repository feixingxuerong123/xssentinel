# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式;
版本号遵循语义化版本。详细的迭代决策记录见 [AGENTS.md](AGENTS.md)。

## [Unreleased]

### Fixed

- **恶意 sitemap 的实体膨胀(Phase 328b)**:stdlib `xml.etree` 会展开内部实体,
  585 字节的 billion-laughs sitemap 实测 >720 MB RSS(8 MB 文档上限无效),
  `--sitemap` 可被一个极小响应打崩。`sitemap_import._parse_xml` 现在在
  `ET.fromstring` 前拒绝任何 `<!ENTITY` 声明(根/子 sitemap 两个解析点),
  AST 守卫钉死所有解析必须经过它;正常 sitemap(含无实体的 DOCTYPE)不变。
  HTML 侧实测为线性放大(100k 层嵌套/1.1 MB ≈1.09 s/67.7 MB),按已知边界记账。

### Verified

- **依赖审计基线(Phase 328c)**:本机 `pip-audit 2.9.0` 对 258 个已安装包量出
  **43 条 / 7 个直接或可选依赖**(aiohttp 3.13.3、urllib3 2.6.3、requests 2.32.5、
  soupsieve 2.8.4、Flask 2.2.5、werkzeug 3.1.8、pytest 8.4.2)。未盲升——aiohttp
  的跨源重定向/解压修复与本仓 egress、brotli 兼容面重叠,Flask 3.x 需 API 回归;
  已落 [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) 与 nightly 非阻断
  审计作业。**隔离 venv 对照**:3.9 全新安装仍 31 条/5 包(修复版均
  `Requires-Python>=3.10`),3.12 全新安装 **0 条**且兼容批 71 passed;
  README(中英)/SECURITY 已写明 3.9 风险,Python 下限是否抬到 3.10+ 待决策。

- **MCP 默认值对齐 + 输出信任边界(Phase 328)**:① **默认值**:`xssentinel_scan`
  此前强制 `dom_engine="off"`(除 `headless`)并硬编码 `max_transforms=8`,而 CLI
  normal 是 `auto`/12——Agent 用默认值会漏掉全部 DOM finding 和 1/3 变换变体,
  且 Skill 宣称 scan 覆盖 DOM。现在两个参数都暴露且默认与 CLI 对齐(`dom_engine`
  可选 auto/playwright/static/off;Playwright 缺失时 auto 自动降级 static);
  `headless` 只负责浏览器确认。② **信任边界**:finding 的 `evidence`/`detail`/
  mined `param` 是目标页面可控文本,MCP 会原样送给 LLM——恶意页面可在反射点附近
  写指令。所有成功结果现在带 `output_safety` 说明与 `untrusted_fields` 列表,
  `initialize.instructions`、scan 工具描述与 Skill 同步声明;证据本身不删除
  (删掉就看不到判定依据)。门禁:新 9 例 + MCP 回归 79 例;ruff 零告警。

- **报告产物私密化 + 重复 CSP 头实测(Phase 326,P2 收尾)**:① **重复 CSP
  头**(实测确认的假阳性):`requests` 把同一响应的多条
  `Content-Security-Policy` 头 join 成一个逗号串,旧 `csp.policies()` 当单条
  策略读 → strict 策略被吞 → 浏览器会拦的页面被判"可绕"(FP 方向)。修复
  `core/csp.py`:保守切分(逗号后须是已知指令名;`a,b.js` 这类源表达式不切),
  str/list 双形态接受;经 `policies()` 的全部判定路径一次修复,零调用方改动。
  ② **报告 0600**:`core/fsutil.secure_write_text`(POSIX chmod 0600;Windows
  明确跳过不做假承诺),接线 CLI 主报告 / PoC 目录 / nuclei 模板 / verify-fix
  与 diff 报告。③ **英文 README**:`README.en.md`(与中文版互链;压缩版按
  新用户视角组织,事实数字与中文版同源)。门禁:新 13 例 + CSP/报告回归 152 例;
  ruff 零告警。

- **MCP 进度/取消 + Agent Skill(Phase 325,P2 落地)**:stdio 传输此前在唯一
  耗时的调用(scan)期间完全失聪——取消通知读不到、Agent 没有进度信号。
  ① **进度**:`tools/call` 带 `_meta.progressToken` 即收到
  `notifications/progress`(progress=已发请求数、250ms 限频、起始 progress=0
  信标);HTTP 传输是请求/响应,明确不宣称有流。② **取消**:
  `notifications/cancelled` 按 request id 中止,在下一个请求前生效(单次在途
  请求为上界),被取消的请求**不回响应**(MCP 规范);`_ToolCancelled` 继承
  `BaseException`,不被 runner 的 `except Exception` 吞掉。③ **线程化
  serve()**:`tools/call` 进 2 线程池、读循环保持监听;响应/进度/错误同锁
  写出,EOF 后 `shutdown(wait=True)` 等全部 worker 写完再返回。④ **Agent
  Skill**:`skills/xssentinel-mcp/SKILL.md`(编排工作流、成本对照、假阴性
  陷阱、进度/取消用法、判定诚意边界)。门禁:新 11 例 + MCP 回归 51 例
  (含子进程 e2e);ruff 零告警。

- **MCP 远程接面(Phase 324,P1 清单落地)**:本周热门缺口 1/2 两条代码项。
  ① **structuredContent + outputSchema(dalfox v3.2.4 同款)**:七个工具在目录里
  声明 `outputSchema`(宽容模式:只钉稳定顶层字段,不 pin additionalProperties),
  `tools/call` 成功结果额外携带 `structuredContent` = 文本反序列化后的同一对象
  ——文本字节不变、只读 text 的 Agent 零感知,**错误结果不带**(不教 Agent 学
  一个永不出现的形状)。7 个 runner 零改动,统一由 `_attach_structured` 附加。
  ② **Streamable HTTP 传输(`POST /mcp` on `--serve`)**:抽取模块级
  `dispatch_message`,stdio 与 HTTP 共享同一实现(守卫测试钉死委托关系),
  两传输不可能答得不一样;GET/DELETE 显式 405(不提供 SSE 升级、无 session);
  批量数组逐条响应、全通知 202 空体、**畸形 JSON 回 JSON-RPC -32700**
  (规范要求,通用 HTTP 400 对 /mcp 路径放行)。安全层全部沿用并逐项测试:
  同一 `--api-key`(401)、同一同源门(跨源 POST 403——最新端点不是墙上唯一
  没砖的一块)、无 key 时 Host 限本机(带 key 远程合法,Phase 190 语义)。
  门禁:新 14 例 + MCP/API 回归 136 + desktop/api_ai_report 55,合计 205 passed;
  改动文件 ruff 零告警。**附记账(既有行为缺口,待后续 phase)**:
  MCP scan 对被过滤端口的快速失败缺失——Windows 对未监听但过滤的端口连接
  ~21s/请求(SYN 重传),扫描每层各试一次 → 单次工具调用分钟级;后续用连接
  超时或 scan 总预算处理,见 AGENTS.md Phase 324。

- **本周热门方向对齐三件套 P0(Phase 323,竞品吸收第十轮)**:来自
  `docs/TRENDING_20261026.md` 的差距清单,三项全部代码级落地:
  ① **MCP `tools/call` 参数校验——未知键拒绝,永不静默丢弃**(对标 dalfox
  v3.2.4 #1464/#1513 的语义级修复):此前 Agent 传错一个键名(如 `cookie`
  单数)会得到**不带认证的"无发现"**——假阴性穿着成功的衣服。现按各工具
  inputSchema 校验:未知键在错误文本里带上可接受键名清单(一轮自我纠正),
  已知同义拼写先归一——REST 名(`target`/`cookie`/`header`/`body`/`parameter`)
  与 JS 驼峰(`maxPayloads`)折叠到规范名;canonical 与 alias 并存时 canonical
  赢。类型面:integer 接受数字串(REST 面同款宽容)、enum 大小写不敏感归一到
  规范成员、bool 严格(bool 是 Python int 子类,显式排除);其余错误形状诚实报
  错。`_tool_call` 从七段重复 if 重构为 `_TOOL_TABLE` 表驱动,守卫测试钉死
  目录与表键集一致。测试 `tests/test_phase323_mcp_arguments.py` 13 例
  (归一化单元 + JSON-RPC 端到端 + 别名对活体反射页往返)。
  ② **终端转义序列剥离(ANSI/VT 注入)**:`core/term_safe.py`——控制台行携带
  目标派生数据(反射串、发现的 URL/参数名、报错文本),带 `\x1b[2J\x1b[H`
  的响应可清屏重写操作者已看到的结论行。三个咽喉点:日志 stream handler
  (`configure_logging`)、进度条(`ConsoleProgress`)、CLI 进程 print 守卫
  (`install_cli_print_guard`,装在 `main()` 包装器、try/finally 出栈卸载,
  `--mcp` 分支进协议前先卸载——stdout 是 JSON-RPC 通道,payload 字节必须
  精确)。剥离范围:CSI/OSC/DCS/ECMA-48 通用 ESC 序列(参数+终态整段),
  尾部裸 ESC,8-bit CSI(`\x9b` 同语法整段),C1 控制块。**存留的 findings/
  报告保持原始字节**——PoC 必须能重放真实参数名;剥离只发生在渲染到终端的
  那一刻。守卫修复了自身递归隐患(safe_print 持有原始 print 引用)。
  测试 `tests/test_term_safe.py` 12 例。
  ③ **CSP-bypass 发现场合并全部 enforcing 策略**(sync+async 双引擎 +
  `advanced_layers` 第三处同形):浏览器只在**每条** enforcing 策略都放行时
  才执行脚本,旧 break-on-first 把"头一条可绕"报成"CSP 可绕"——策略二更严的
  页面上是系统性假阳性。现 all-bypassable 才发 finding,evidence 聚合各策略
  weak,`csp_header` 展示字段用 ` || ` 连接全部策略(无程序化消费者,已核);
  `advanced_layers` 给 TT/nonce 层的解析从 `_enf[0]` 改为全策略 join——nonce
  只声明在第二条策略时原来不可见,TT 正则消费方对 join 串逐正则扫描语义不变。
  测试 `tests/test_phase323_csp_multipolicy.py` 13 例(FP 类双向、单策略字节
  等价回归、双可绕聚合、join 串到 nonce/TT 正则消费方的可达性、源形守卫)。
  门禁:定向批 **329 passed + 1 skip**(新 38 + MCP/CSP/logger 回归批 143 +
  CLI e2e 红队/async 管线 48 + 进程内 CLI 驱动 100)+ `test_benchmark.py`
  35 例全绿(双引擎全管线);改动文件 ruff 零基线。全量分批门禁按惯例未跑,
  「未验证」记账。

- **对齐 2026-10 安全热门方向的四线落地(Phase 322,竞品吸收第九轮)**:
  ① **MCP 工具面 3→7**(HexStrike/Deadend 式 Agent 细粒度范式):新增
  `xssentinel_verify`(单载荷回放+同一确定性判定器,Agent 的调整-重试循环;
  无执行点载荷诚实标注「可反射、不可确认执行」)、`xssentinel_param_mine`
  (Arjun 血统差分挖参,一次一名有界)、`xssentinel_csp_analyze`(一次请求读
  header+`<meta>` 双通道,按 script-src-elem/attr 分族报内联放行;Phase 196b
  契约)、`xssentinel_propose`(见④)。`tests/test_mcp_server.py` 20 例 +
  `tests/test_llm_propose.py` 17 例(假 pool 全桩无网)。
  ② **场景语料正式化**:`data/scenarios.json`(带 `_meta` 贡献契约;`--scenarios
  builtin` 别名直达),新增 `{self}` 占位符表达「写回同一页再读回」的 self-echo
  存储型 XSS(唯一不需要应用端点知识的通用存储形状);GET 写入变体经活体测量
  证明语义不成立(read 步会覆写自己的写入)已记入 `_meta.non_goals` 不发布。
  占位符三向闭合测试:语料广告的每个占位符必须在 `run_scenario` 源码里真实展开。
  ③ **nuclei dast 桥接 + `--custom-payloads` 死接线修复**:`core/nuclei_import.py`
  提取 XSS 相关字面载荷(模板不执行;interactsh 依赖载荷、DSL 占位符、路径形状
  字符串三类诚实跳过并计数)。接线时发现 `--custom-payloads` 自 CLI 进 Scanner
  后**零消费点零测试**——已复活:双引擎候选队列 prepend(操作者显式意图优先,
  max_payloads 仍封顶;无执行点载荷在门口丢弃),`verifier.has_execution_point()`
  公共助手供两引擎与 MCP verify 共用。**本机 dast 快照实测:251 模板 0 导入**
  (72 OOB + 81 DSL 占位符 + 228 非 XSS)——桥接正确但该快照无可导内容,诚实记账;
  XSS 专用模板集/未来月度增长才是消费面。
  ④ **LLM 提议-验证管线**(`core/llm_propose.py` + `xssentinel_propose` 工具):
  模型只提议,每条候选经 mark() 打新 token 后真回放,`verify_semantic`(可选
  verify_headless)是唯一裁判——confirmed=令牌执行,未确认=unverified 如实上报;
  确认的提议**不**自动晋升进交付语料(晋升是评审决策,Phase 318 纪律)。pool
  未配置/耗尽诚实报错。判定语义零变化:这是回放路径,不是检测路径。
  ⑤ **XSSMaze xsleak 记分契约版本化**(`benchmark/xssmaze_scoring.py` + 8 例纯
  函数测试):上游 v0.3.0「xsleak 全类是 cross-site leaks,报 0 才正确」的口径
  从 README+记忆钉进版本化代码;dev 归因工具每次跑官方 runner 结果都做交叉核对,
  上游若重新分类会响亮报 CONTRACT MISMATCH 而不是静默漂移 FN 分母。
  官方 runner 仍是唯一权威记分者,本模块不重记分。
  门禁:受影响面定向批全绿(MCP 20+17、场景 10、桥接 16、契约 8、async 管线/
  phase311 20);改动文件 ruff 零基线;引擎对等门与全量分批门禁结果见 AGENTS.md
  Phase 322 条目(未跑完的按「未验证」记账)。

- **第三方靶场(OWASP Juice Shop 20.2.0)五行矩阵全测(Phase 270,无出口代理)**:目标是官方
  20.2.0 树(`build/` + `node_modules/`,Node 22),ground truth 来自应用自身的 Angular
  路由与上游 `challenges.yml`,每行都走真实 CLI。同一目标、同一提交:

  | 行 | 命令要点 | findings | 请求 | 用时 |
  |---|---|---|---|---|
  | oneshot(交付目标) | `-u <root> -c --crawl-depth 1 --headless` | **1** `dom_dynamic` high/high browser-executed @ `#/track-result?id=xss` | 826 | 77s |
  | discover | `-u <root> -c --discover --headless` | **1** 同一 sink | 10,685 | 1059.7s |
  | dom-route | `-u <root>/#/search?q=apple` | **1** @ `#/search` | 39 | 12.0s |
  | dom-route-result | `-u <root>/#/search-result?q=apple` | **1** | 39 | 12.9s |
  | api-surface | `-u <root>/rest/products/search?q=apple` | **0**(该端点不是 XSS 面) | 53 | 2.4s |

  **能力与可发现性分开记账**:handed-route 行 12 秒命中;爬取行 77 秒也命中,说明路由矿机
  在真实 bundle 上确实工作(5 条 hash 路由)。`discover` 用 **13 倍请求、13 倍时间**换来
  同一结论 —— 该行目前是负收益,除非目标是"证明能自己找路"。
  交付目标行用 `--crawl-depth 1` 取证:深度 2 在本机 25 分钟 0 连接(楔死,Phase 219/269
  同形),不是产品结论。`discover` 跑完靶进程被 V8 OOM 打死(Phase 165 同形),属靶场容量。
  全程 **零非预期 finding**:四条命中是同一个已证实 sink,`api-surface` 正确保持沉默。
  前置条件:`NO_PROXY=127.0.0.1,localhost`(见 Phase 268 的代理假阴性)。

- **登录后的存储型 DOM 链路:第 7 条挑战确认,召回 3/9(Phase 275)**:`--stored-dom`
  早就支持 `--login-token` + `--browser-local-storage`,但那条路从没在真实应用上跑过
  (Phase 274 只走了 HTTP 视图)。实测(OWASP Juice Shop 20.2.0,管理员会话):

  ```
  --stored-inject /api/Feedbacks  --stored-view /#/administration
  --stored-param comment --stored-dom
  --stored-extra rating=5 --stored-extra captchaId=… --stored-extra captcha=…
  --login-token <JWT> --browser-local-storage token=<JWT> --headless
  => 1 finding: stored_dom high/high browser-executed
     sink Element.innerHTML @ #/administration,41 requests,29s
     payload "<<script>Foo</script>iframe src=\"javascript:alert('xssv_…')\">"
  ```

  **独立裁决**:同一条存储行用真实 Chromium 打开 `/#/administration` 并监听 dialog,
  得到 **两次 `alert('xssv_…')`** ⇒ 真执行,不是 taint 误报。服务端 sanitize-html 剥掉了
  `<img onerror>`/`<svg animate>`/`<script>` 的常见形状,却放过了 `<<script>` 前缀的
  polyglot —— 这正是"Server-side XSS Protection"要的那条绕行。
  召回账 2/9 → **3/9**。两条臂这次给出互补答案(JSON 视图 inert、登录 SPA 视图 fired),
  是"HTTP 臂 + 浏览器臂都要保留"的直接证据。未动判定语义,不触发全量 192 的规矩。

- **第 6 条确认,但扫描器那条载荷只到 sink 不到执行(Phase 276)**:同一套登录后
  浏览器链路换成注册接口:

  ```
  --stored-inject /api/Users --stored-param email --stored-json
  --stored-extra password=Passw0rd! --stored-extra passwordRepeat=Passw0rd!
  --stored-view /#/administration --stored-dom
  --login-token <JWT> --browser-local-storage token=<JWT> --headless
  => 1 finding: stored_dom high/high, sink Element.innerHTML, 41 requests, 32s
  ```

  **独立取证把这条件拆开了**。管理员页 DOM 里,扫描器 token 的实际形状是
  `<span class="error">&lt;<script>Foo</script>iframe src="javascript:alert('xssv_…')"&gt;</span>`:
  首字符被转义,`<script>` 是 innerHTML 插入的节点(**不会执行**,HTML 规范),所以它的
  token 没有任何弹窗。但同一页面用 `<iframe src="javascript:alert(2)">@juice-sh.op`
  注册的账号**真的弹了 `alert(2)`** ⇒ 端点确实可利用(挑战 #6 成立),
  而扫描器那条 finding 的证据等级是"到达 sink",不是"执行"。
  **记账**:`stored_dom` 的 `browser-executed` 目前把"到达 sink"和"弹窗执行"算成同一类;
  是否像 Phase 265 对 `dom_dynamic` 那样拆成 `stored_sink_reachability`,属于判定语义改动,
  要跑全量 192 并有明确决策,本轮**不做**,只把观测写下来。

- **Phase 279 尝试拆分 `stored_dom` 证据等级,已回退(全量门禁变红)**:照 Phase 265 对
  `dom_dynamic` 的做法,把"到达 sink 未观测到执行"从 `stored_dom`/high 拆成
  `stored_sink_reachability`/low(无 proof),并接进 report/SARIF/建议/合规/PoC/控制台。
  **全量 192 双引擎门禁结果**:async **FP0 FN0 ERROR0(182 例)**,sync **FN=2**
  (pos-stored-02 / pos-stored-03)。
  根因量到一半:`scan_stored_dom` **只取 3 个载荷、且第一个命中就返回**,语料顺序是
  `<<script>…iframe`(不可执行)→ `<script>`(innerHTML 内不执行)→ `<svg/onload>`,
  真正会执行的 `<img src=x onerror=…>` 排在**第 4**;引擎对这三个都回 `executed=False`,
  于是两个真漏洞页被降级成"投递线索" ⇒ FN。把候选放宽到 8 个后仍未在本轮内拿到执行证据。
  **处理:整体回退**(不交红门禁),判定语义保持原状;两条可选路径留给决策:
  ① 探测持续到出现执行证据(改探测策略,不动判定);② 拆分并把 `stored_sink_reachability`
  计入这两个 benchmark 用例的 `finding_types`(改基准口径,意味"低提示也算检出")。
  教训也留一笔:回退时用 `git checkout HEAD -- <file>` 会**连带抹掉该文件里别人的未提交
  WIP**(本次抹掉了 Phase 265 在 findings/report/poc/validation/compliance/fix_advice/
  控制台 六处的 `dom_sink_reachability` 接线),已逐项按原文恢复,41 例测试全绿。

- **Phase 280:存储型 DOM 探测改为"探测到执行为止",不动判定语义(回到路径 ①)**:
  Phase 279 回退后照路径 ① 修**探测策略**,finding 类型/等级一律不变:
  ① 命中不再是终止条件——`executed`(引擎自己的字段)/`sink == "dialog"` 才是;投递型命中
  只记下第一个作兜底,继续试后面的载荷。
  ② 候选面从 3 放宽到 **6**(`_STORED_DOM_PROBE_BASES`)。
  ③ 候选面**按可执行性重排**:带行内事件处理器(`<img src=x onerror=…>`、`<svg/onload=…>`
  `<details open ontoggle=…>`)排前面,`<script>` 与 `<<script>…iframe` polyglot 排后面
  —— 前者进 innerHTML 会真的建元素并触发,后者按规范不执行,而语料顺序偏偏把惰性形状放最前。
  **实测**:st02 由"只报惰性 polyglot"变成报 `<img src=x onerror=alert('xssv_…')>`,
  sinks `Element.innerHTML, dialog`,dialog 真把 token 带出来;单例耗时 32–35s(harness 每例
  预算 60s)。**全量 192 双引擎门禁**:sync **FP0 FN0 ERROR0 / 192 scored / 0 SKIP**;
  async **FP0 FN0 ERROR0 / 182 scored / 10 SKIP**(那 10 条存储型用例本就是 sync-only)。
  测试 `tests/test_stored_dom.py` 11 例(新增"探测不终止于投递型命中"
  与"执行证据落在第 N 个载荷上也要报那个载荷")。
  **真实靶场复测(Juice Shop 20.2.0)顺带解决了 Phase 276/278 留下的两条 caveat**:
  同一套链路重跑,#6 报 `<img src=x onerror=alert('xssv_fc4e81fa')>`、#9 报
  `<svg/onload=alert('xssv_45f68b71')>`,两者都用独立 Chromium 监听到了**自己的 token**。
  即"扫描器载荷只到 sink"从来不是判定问题,是**探测问题**——修探测即可,不需要放宽判定,
  这也是 Phase 279 的拆分最终没有必要的直接证据。

- **Phase 281:存储注入支持 PUT/PATCH(非 GET 方法都带 body)**:`--stored-method` 的
  choices 只有 GET/POST,而存储层把 PUT/PATCH 当成“非 POST”走 query 参数分支——REST 更新写入
  的载荷永远到不了 body 解析器(Juice Shop 的 API-only XSS 正是 `PUT /api/Products/:id`)。
  现在 choices 放开到 GET/POST/PUT/PATCH,层里改成“非 GET 即带 body”。测试 44 passed。
  **第 5 条实测(OWASP Juice Shop 20.2.0)**:`PUT /api/Products/1` + Bearer 管理员 ⇒ 200,
  `description` 原样落库(`<iframe src="javascript:alert(1)">` 读回原样);但渲染面是
  **点击产品卡片才开的详情对话框**,搜索页只渲染 name 且**已转义**
  (`alt="&lt;img src=x onerror=...&gt;"`),description 根本不进搜索页 DOM
  ⇒ 独立 Chromium 打开 `/#/search?q=…` 零弹窗、payload 不在 DOM。
  **结论:第 5 条的阻塞点从“需管理员会话 + 写”精确到“写入已通,但渲染面需要一次点击交互,
  URL 式 `--stored-view` 表达不了”**。可行方向:把存储型验证接进已有的场景 DSL(多步流),
  或给 `--stored-view` 加“打开后点击选择器”的可选动作。

- **Phase 282:`--stored-view-click`(打开视图后点一下),以及一个新发现的归因问题**:
  给 `--stored-view` 加可选动作 `--stored-view-click SELECTOR`:浏览器加载视图后、观测 sink 前,
  点**第一个**匹配元素(对话框/抽屉/手风琴都属"渲染在一次点击之后"的形状)。
  `DynamicDomAnalyzer.analyze` 新增 `click_selector`(默认 None,行为不变);测试 46 passed。
  **第 5 条复测仍没拿下,且暴露出比"点不到"更严重的问题**:
  ① 该页有 consent 遮罩(`cdk-overlay-backdrop … intercepts pointer events`),首卡点击被拦;
  ② **归因不干净**——`scan_stored_dom` 把同一个 token 同时当"存储载荷 marker"和引擎 URL 探针的
  marker,而 `_probes()` 会把 marker 注入 `location.hash/search/href/cookie/referrer/window.name/
  postMessage`。视图页只要把任一 URL 源反射进 sink,token 就到 sink 了,**这条 hit 可能整个来自
  URL 反射,与存储载荷无关**。回放也支持这个解释:把 finding 的载荷原样写回,页面上根本看不到那个
  token(点击前/后都不在 DOM,dialogs 为空)。
  **处理**:`--stored-view-click` 保留(能力成立、已测),第 5 条标**未确认**,修法记录在案:
  给引擎加"探针 marker ≠ 存储 marker"(存储路径传两个 token)。本轮最值钱的发现不是"点不到",
  是**同名 marker 让两种来源无法分辨**。

- **Phase 283:关闭存储路径的 URL 探针,消掉"假 stored 命中"(归因修复)**:
  `DynamicDomAnalyzer.analyze` 新增 `url_probes: bool = True`;`scan_stored_dom` 传
  `url_probes=False`——命中本身已经在页面数据里,引擎只做一次纯导航 + 交互分发,
  不再把 marker 推进 `location.hash/search/href`、cookie、referrer、window.name、postMessage。
  **修复效果(同一套链路复测)**:#5 API-only 的 `stored_dom` high **消失了**
  (Phase 282 里那条确实来自 URL 反射);#9 HTTP-Header **照旧报出**
  `<svg/onload=alert('xssv_be1ca9a9')>`——真存储命中不受影响。
  **全量 192 门禁**:sync **FP0 FN0 ERROR0 / 192 / 0 SKIP**(基准的存储型用例未受影响)。
  还要回头复核 Phase 275/276/280 那几条:它们当年的命中里**可能混有 URL 探针贡献**,
  需要在新行为下重测才算数。

- **`--stored-view-click` 现在可重复(按顺序点多次)(Phase 284)**:分页视图一次点击不够——
  存储的行落在第 3 页,"Next page" 得点两次。原来 `store_true` 式的单值开关做不到,
  现在 flag 改成 `action="append"`,`analyze(click_selector=[...])` 按**顺序**点。
  **实测边界(诚实记账)**:Juice Shop 管理员反馈表(10 行/页)上点两次 "Next page"
  **没能救回第 7 条**——该页 consent 遮罩让 Playwright 的可点击性检查超时(和 #5 同一个
  遮挡)。试过 `dispatch_event("click")` 兜底能"点成功",但应用其实没收到交互,属于
  **静默假成功**,比看得见的漏报更糟 ⇒ **故意不做这个兜底**,失败就报失败。
  能力本身留着(可重复点击是通用形状),测试 `tests/test_stored_view_click.py` 5 例。

- **同一靶场的召回账:9 条 XSS 挑战,当前可复现 5 条 + 1 条曾确认但已不可复现(Phase 270/275/276/278/285,283 后复核)**:
  上游 `data/static/challenges.yml` 共 **9 条 XSS**,逐条对照(不把"没测"算成"没漏"):

- **Phase 285:第 8 条(CSP Bypass)确认,根因是语料缺口**:`usernameXssChallenge` 的机制是
  用户名经**自家 RegEx 净化**后由 Pug 旧页 `/profile` 渲染,而该页的 **CSP 由
  `user.profileImage` 拼出来**(`img-src 'self' ${profileImage}; script-src …`)⇒ 可 CSP 注入。
  手工对照实测:`<script>alert('…')</script>` 被剥(或不执行),**`<<a|ascript>alert(…)</script>`
  实弹**(`dialogs ['xssv_c8b']`)。查语料:**没有这个形状** ⇒ 不是能力缺口是语料缺口。
  在 `data/payloads.json` 补 1 条(最小插入:1 增 0 删),置于 html_element 首位以进入
  `scan_stored_dom` 的探测面。补后扫描器实测:
  `stored_dom high/medium`、载荷 `<<a|ascript>alert('xssv_ab7ee4e3')</script>`、
  **sinks `dialog`**、`headless.fired` ⇒ 真执行证据(不是 sink 到达)。
  confidence 是 medium 而非 high:注入面 == 视图面(`/profile` 自视图),按既有口径
  "未证明对其他访客渲染"降级——这是对的,不是漏判。
  前置条件记清楚:该页 CSP 需先用 `POST /profile/image/url`(urlencoded)
  注入 `imageUrl=*; script-src 'unsafe-inline'`;写入用 `POST /profile` 且**要 cookie 认证**
  (`-b token=…`),`PUT /api/Users/:id` 是 `denyAll`(恒 401)。

  | # | 挑战 | 面 | 状态 |
  |---|---|---|---|
  | 1 | DOM XSS | `#/search?q=` | **已确认**(browser-executed) |
  | 2 | Reflected XSS | `#/track-result?id=` | **已确认**(browser-executed) |
  | 3 | Bonus Payload | 同 #1 的输入框,换载荷 | sink 已覆盖;该载荷变体未单独测 |
  | 4 | Video XSS | 促销视频 URL | 未测(需要另一条上传面先行) |
  | 5 | API-only XSS | `PUT /api/Products/:id` → 产品详情对话框 | **仍未确认(Phase 283)**:URL 探针已关闭，假命中消失；余下的阻塞是该页 consent 遮罩拦住点击（对话框打不开）——属于目标交互，非检测能力 |
  | 6 | Client-side XSS Protection | 注册用户 → 后台用户列表 | **已确认(Phase 276 → 280 升级)**:`POST /api/Users` 的 email 原样落库;Phase 280 探测修复后扫描器自己的载荷 `<img src=x onerror=alert('xssv_…')>` 在管理员页**实弹**(独立 Chromium `dialogs ['xssv_fc4e81fa']`),不再是“只到 sink” |
  | 7 | Server-side XSS Protection | Customer Feedback 评论 | **❌ 不可复现(Phase 283/284 复核)**:写入成功(API 里 33 条含 marker),但管理员 feedback 表只渲染 **≤10 行且 "Next page" 禁用** ⇒ 我们的行**从未进入 DOM**;翻页与点同意都无效(同意按钮点击超时)。Phase 275 那条命中**高度可能是 URL 探针贡献**(Phase 283 已关闭该行为) |
  | 8 | CSP Bypass | `/profile` 旧页(RegEx 净化 + CSP 由 profileImage 拼出) | **已确认(Phase 285)**:补语料后扫描器自载荷 `<<a|ascript>alert('xssv_…')</script>` 实弹(sinks `dialog`、`fired`);需 cookie 认证 + 先做 CSP 注入两步 |
  | 9 | HTTP-Header XSS | `True-Client-IP` → 最后登录 IP | **已确认(Phase 278 → 280 升级)**:`--stored-header` + `--stored-relogin` 写入后,Phase 280 让扫描器自己的载荷 `<svg/onload=alert('xssv_…')>` 在最后登录 IP 页**实弹**(独立 Chromium `dialogs ['xssv_45f68b71']`);此前(Phase 278)它只到 sink |

  准确读法:矩阵证明的是**精度与交付链路**(0 条非预期 finding);**当前可复现的召回是
  5/9**(#1/#2/#6/#8/#9),#7 已落到"不可复现:该视图不渲染扫描器写入的行"(见该行)。
  剩余 4 条里 #5 是被目标交互挡住(consent 遮罩),#4 依赖另一条上传链,
  #3 是同 sink 的载荷变体,#7 属目标视图不渲染 —— 都不是检测层漏报。
  #6/#9 在 Phase 280 后已由扫描器自己的载荷**实弹**(独立 Chromium dialog 复现),
  不再是"sink 到达"级别。
  **⚠️ 已确认的行要周期性重测**:#7 这次就是 Phase 283 关掉 URL 探针后复核出来的——
  一个"已确认"如果只在某种目标状态(空库)或某种引擎行为(探针开着)下成立,
  它就该被标注,而不是一直留在"已确认"栏里。

- **Phase 288:归档遍历写入载体(zip-slip)—— Juice Shop #4 从"依赖另一条上传面"到扫描器自载荷实弹,召回 5/9 → 6/9**:
  机理(实测,`dev/_p287_row4.py` + 独立 Chromium 单变量 A/B):`POST /file-upload`
  (multipart,免认证)的提取器不 sanitize 条目名 ⇒ zip 内 `../../` 条目可覆写磁盘文件;
  `/promotion` 把 promo .vtt **内联**进 `<script id="subtitle">`,文件内容里的
  `</script>` breakout 即执行。扫描器侧断点定位:上传探针(Phase 48/90)只发单文件、
  从不发归档 ⇒ **写原语缺失**;观测臂(stored-DOM 浏览器臂 + Phase 194 dialog 通道)
  已具备。上传端点自动发现(BP-1)与盲猜遍历目标(BP-3)按项目惯例**不做**——
  写入类原语保持操作者声明(opt-in),与 `--stored-*` 家族一致。
  落法:`scan_stored_dom` 增归档载体(`--stored-archive-entry PATH` +
  `--stored-file-field NAME`,**仅 sync**——该方法本无 async 对偶,manifest 存储型用例
  本就是 `engines:["sync"]``),zip 内存构建、multipart 文件名干净(遍历只在条目名里,
  **不存在 requests 对 `../` 的百分号编码问题**)、首探针为 `</script>` breakout 形状
  (模块常量,**不进语料**——Phase 285 教训:语料插入扰动共享探测预算)、伴生字段仍走
  `--stored-extra`;flag 缺 `--stored-dom` 时**告警不静默**(async 模式下
  `--stored-dom` 本就在 sync-only 警告列表里,两条路径都诚实)。
  基准锁定:服务端新 mode 三件套(不收 sanitize 的提取器 / 剥路径的安全孪生 /
  把目标文件内联进 `<script>` 的**共享视图**=单变量),manifest +2 例
  (`pos-upload-02` / `neg-upload-02`,矩阵 192 → 194),runner 增
  `stored_archive_entry` 字段翻译。
  证据:单测 `tests/test_stored_archive_write.py` 6/6;e2e 正例 `stored_dom` high/high
  browser-executed(dialog)、负例 0 findings、**反证**(去掉 flag 同一命令)0 findings;
  **全量 194 例门禁 FP0 FN0 ERROR0 / 0 SKIP**(`benchmark_20261021_185204.json`,
  含 pos-upload-02 TP / neg-upload-02 TN);**真实目标复现**:`stored_dom` high/high
  browser-executed,`proof.sinks=dialog`、
  `proof.archive_entry=../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt`,
  测后 vtt 按 sha256 还原并复验 byte-identical。
  **台账 #4 行**相应由"未测"改"已确认(Phase 288)"、可复现召回 6/9;该行修订随台账
  所有者的下一次提交(台账区当前是他人未提交 WIP,不代为改动)。

- **Phase 289:第 5 条(API-only XSS)确认,零新检测代码——UI 态门闩用 `-b` cookie 播种绕过,召回 6/9 → 7/9**:
  Phase 281–284 把 #5 的阻塞记作"consent 遮罩拦住点击"。本轮把机制钉死:遮罩不是
  cookie 同意横幅,是 Juice Shop 的 **Welcome 引导对话框**(`mat-dialog-container`
  + `.cdk-overlay-backdrop-showing`,关闭按钮 `.close-dialog`);点掉它写 cookie
  `welcomebanner_status=dismiss` 且跨加载持久化。而 `-b/--cookie` **本来就进
  requester jar、并经 auth_state 播种进浏览器臂**(Phase 150 的机制,只是没人往这个
  方向用过)——操作者知识就是输入,扫描器负责把它变成执行证据,与 `--stored-*` 家族
  同一哲学。完整配方(全部既有开关,无一行新检测代码):
  `-b welcomebanner_status=dismiss` + `--login-json --login-field-user email`
  (该端点要 `email`,默认 `username` 会让登录静默失败)+
  `--stored-inject POST /api/Products --stored-json --stored-param description
  --stored-extra name=<唯一名>` + `--stored-view "#/search?q=<唯一名>"` +
  `--stored-view-click mat-card` + `--stored-dom`。
  实测:`stored_dom` high/high browser-executed、`proof.sinks=Element.innerHTML`、
  载荷 `<svg/onload=alert('xssv_…')>`(详情对话框由 `[innerHTML]` 渲染;
  Phase 283 关掉 URL 探针后归因干净)。代码侧只做一件事:把 main.py 里
  "jar → 浏览器 cookie dicts"的内联推导式抽成 `_jar_cookie_dicts()(原不可测),
  3 个新单测锁住"操作者 cookie 与登录 cookie 同车进浏览器、且形状过 Phase 174 的
  url-vs-path 规则"(tests/test_auth_cookie_dicts.py)。
  **教训**:"目标交互挡住"的结论要先问"这是目标特性,还是操作者知识没喂进去"——
  Welcome 对话框有 dismiss cookie,`-b` 早就能表达它。
  台账 #5 行随之改"已确认(Phase 289)",可复现召回 **7/9**
  (#1/#2/#4/#5/#6/#8/#9;余 #3 变体读数在并行会话手里、#7 属目标视图不渲染)。

- **Phase 290:async 引擎接上覆盖记账——此前每份 `--async` 报告的 coverage 全是 0**:
  量到的三层断点:① `AsyncScanner` **根本没有 CoverageTracker**(sync 自 Phase 20-3 就有);
  ② 报告由**同步 Scanner shim** 组装,shim 自带一个空 tracker 且从未拷贝 async 的;
  ③ 58 个 sync 子层的 `touch_layer` 全落进 shim 的**内存 `_NullCoverage`**(Phase 63 的
  可运行占位),永远到不了报告。⇒ 一个刚产出 4 条 finding 的 async 扫描,报告写着
  "0 端点 / 0% 层 / 0 请求"(与 Phase 267「门禁看不见浏览器跑没跑」同族的**静默零仪表**)。
  落法:AsyncScanner 持真 tracker;shim 的 facade **委托**给它(保留 `touched` 供测试,
  签名改 `*a/**kw` 原样转发——窄签名曾把 `record_param(method=…)` 的 TypeError 喂进层的
  except,静默停掉整个 header/path 层,3 个测试因此变红);async 原生层补规范 ID
  (`L3_dom_static`/`L6_dom_dynamic`/`L7_csp`/`L7_jsonp`/`L7_cors`/`L7_xsleak`/
  `L9_upload_filename`/`L5_blind_oob`/`L1_reflected`/`L7_csp_nonce`/`L7_csp_gadget`/`L2_hpp`),
  `_touch_coverage` 对 `__new__` 构造的测试替身容错;finding 计数只走 `_add_finding`
  单一入口(facade 不转发,否则双计 7 对 4);请求计数**归因到当前端点**
  (模块级 `_set_current_scan_url`,path/error 层把载荷注入 URL 本身,按探针 URL 记会凭空
  多出 17 个端点行);session 边界 + 线程卸载的 sync Requester 两条通路都计数
  (后者用实例方法包装,`Requester.get/post` 不经过 `request`,逐 verb 包才全)。
  **实测(两页夹具,双引擎对照)**:async 4 findings / 3 端点 / 4 finding 计数 / 28 层,
  sync 4 / 3 / 4 / 27——端点与 finding 计数**逐项对齐**;请求数 async 计**全部传输请求**
  (168),sync 计层站点(83),两者语义不同、未强拉齐(如实记录,不在同一字段上假装可比)。
  **改坏过三处、都由测试/对照抓回**:① 计数包装写成 `async def` 破坏了 aiohttp
  `async with session.get(...)`(async 4 findings → **0**);② `isinstance(session,
  ClientSession)` 的 `_transport_is_real` 判定被包装类破坏 ⇒ 同步层降级离线
  (header/path 2 findings → 0);③ `Finding` 只有 `.data` 没有 `.url/.method`,
  `_add_finding` 的记账一直在 AttributeError 里静默为 0。新增
  `tests/test_async_coverage.py` 5 例;async 套件 **123 passed**(唯一失败
  `test_async_budget::…confirming_endpoint` 在干净 HEAD 上同样失败,预存非本轮)。
  边界:请求数字两引擎语义不同;`_NullCoverage.record_finding` 故意不转发。

- **Phase 291:WAF 指纹误检——CSS 里的 `surface-variant` 被当成 Cisco ACE,`const tsa` 被当成 F5**:
  Known limitations 第 5 条("Juice Shop 被判 Generic/Unknown WAF / Cisco ACE")本轮量到
  根因,不是泛泛的"误检":① Cisco ACE 规则的 `ace-` 命中了 Angular/Material 的 CSS
  自定义属性 `--mat-sys-on-surface-variant`(及 `interface-header`/`space-around`
  这类连字符类名);② F5 BIG-IP ASM 规则里的**裸 `tsa`** 命中 `const tsa = …` /
  `computeTsA(…)`——该 token 全仓库无任何依据(无文档、无测试),大概率是笔误。
  ⇒ 任何普通前端页面都可能被判成"在 WAF 后面",于是扫描器为一个**不存在的 WAF**
  生成 evasion 变体(白烧预算),报告也误导操作者去调 WAF 绕过。
  修法:两条规则收紧——Cisco 用 `\bace-` 锚定(保留真 `ACE-…` cookie/头,拒绝连字符
  散文),F5 去掉裸 `tsa`(真指纹 `BIGipServer`/`TS0…`/`f5ip`/`webshields` 都在;
  `ts01` 本就被 `TS0[0-9a-f]+` 以 re.I 覆盖)。
  证据:合成分片——CSS 变量/类名/JS 标识符 → `waf=None`(修前分别为 Cisco ACE /
  Cisco ACE / F5);真 `ACE-abc=1` cookie / `BIGipServerpool_80` / `TS01a1b2c3`
  / 正文含 "Cisco" → 仍正确命中。Juice Shop 实例(无 WAF)修后 `waf=None`。
  测试 +6(`tests/test_waf_detect_block_hints.py::TestFingerprintSpecificity`),
  WAF 单测 16 passed。全量门禁另跑(见提交信息)。

- **Phase 292(docs):Known limitations 五条按实测清算** —— ①②("两条通用证据规则")
  **已由 Phase 218 解决**(`cap_unverified_severity`,双引擎最终出口);③(DOM 参数名)
  **部分解决**(带参/hash 路由现在有 `param=q@hash`,无参页面 `None` 是诚实的);
  ④(async 爬取页层)**已由 Phase 214–216 解决**,Phase 290 双引擎逐项对照复核;
  ⑤(WAF 误检)**Cisco ACE 已修**(Phase 291),`Generic/Unknown` 待靶机可用时复测;
  ⑥(爬取宽度不稳定)**仍开放**。逐条状态与新判据见下方"Known limitations"节。

- **Phase 293:爬取宽度"双峰"的真相——loop 卡死后静默回退静态 BFS;修成"可修复 + 必可见"**:
  Known limitations ⑥(同命令 18 / 22 / 70 / 70 / 70 / 74 端点)本轮量到机制:
  **双峰 = 两种引擎**。浏览器爬取正常时 ≈70-74 端点;dom_engine 的**共享 sync 浏览器**
  一旦在进程里跑过(留下运行中的 asyncio loop),爬虫自己的 `sync_playwright()` 就报
  "Sync API inside the asyncio loop"→ 爬取中止 → **静默回退**静态 BFS(≈18-22)。
  直接复现:共享浏览器活着 → **0 端点 / 0.0s**;`shutdown_thread_browser()` 后 →
  **13 端点 / 30.5s**。
  修法两层:① **可修复**——识别 loop 卡死特征,先 `shutdown_thread_browser()` 再
  **重试一次**(实测:同一场景从"0 端点 + 回退"变成"13 端点、engine=spa、未回退");
  ② **必可见**——三条回退分支(Playwright 不可用 / 导入失败 / 爬取中止)不再只打
  verbose print,一律 `_log.warning`,并把 `engine_used`(`spa`/`static`/`static-fallback`)
  与 `fallback_reason` 写进报告(`crawl_engine` / `crawl_fallback_reason`)。
  **report.build_json 是固定 schema**——新键必须显式加进 `out`,否则 `meta` 里有也被丢弃
  (本轮实际踩到:字段"没出现"被误读成"没写入")。
  测试:新增 `tests/test_crawl_fallback_visibility.py` 5 例;既有
  `test_spa_crawler_fallback.py` 的 abort 断言从"捕获 stdout print"升级为"捕获
  warning 日志 + engine/reason 状态";爬取/SPA 整组 **104 passed / 9 skipped**。
  边界:HTML 报告的头部暂未展示该字段(JSON 已含);`Generic/Unknown` 复测与
  爬取宽度的**残余方差**(页面预算 8s 截断)属另项。

- **Phase 294:"blocked" 的证据精度——厂商名/主题词不再等于"被拦",这是静默 FN 源**:
  量 Known limitations ⑤ 尾巴时发现比"WAF 误检"严重得多的问题:`_BLOCK_BODY_HINTS`
  里混着**厂商名与主题词**(`waf`/`cloudflare`/`cf-ray`/`akamai`/`firewall`/
  `security policy`/`malicious`/`request id`/`rule id`/`protected by`,以及中文的
  `攻击`/`防火墙`/`安全策略`、日文 `ファイアウォール`、`pare-feu`/`Firewall`…)。
  而 `blocked=True` 会让 `_try_payload` **丢弃载荷**(Phase 122 记过的同族静默 FN)。
  实测:JS 变量 `wafEnabled`、CSS 类 `waf-banner`、单词 `wafer`、"What is a WAF?"、
  错误页 "Request ID: …"、营销页 "Next-gen firewall"、安全看板
  "malicious requests blocked this week"、中文安全文章 "攻击面与防火墙配置" ——
  **全部判 blocked**;更糟的是 **Cloudflare 前置站点的放行 200 响应**(CF 会注入
  Ray-ID 注释)也被判拦 ⇒ 真实世界所有 CF 站点的载荷被成批丢弃。
  状态路径同样过宽:`_BLOCK_STATUS` 含 401/404/400/500/502,只要带厂商头就把
  "缺页/要认证/源站崩"当"被拦"。
  修法:hint 表只留**拒绝类短语**(request blocked / access denied / blocked by /
  attention required / 访问被拒绝 …),厂商名归指纹(1-3 轮已用),不再当拦截证据;
  `_BLOCK_STATUS` 收窄为 {403,406,419,429,444,451,493,503,999}(401/404/400/500/502
  移出)。真拦网页(403+CF block page、200+"Request blocked by policy"、中文
  "访问被拒绝")仍判拦。
  证据:17 例矩阵全过(10 个良性样本全 `blocked=False`、CF 放行页 `waf=Cloudflare`
  但 `blocked=False`、404/401+CF 头不拦、4 个真拦网页仍拦);benchmark 端到端
  **pos-waf-01 仍 1 条 reflected**(naive WAF 升级绕过照常)、**neg-waf-01 仍 0 条**。
  测试 +6(`TestBlockEvidencePrecision`),WAF 单测 22 passed;全量门禁另跑。

- **Phase 295:WAF 规则的"良性语料回归网"** —— 291/294 两轮修的是**同一个形态**
  (规则在普通文本上误触发),而且都是手工逐个量出来的。补一张 20 样本的良性语料表
  (Material CSS 变量、Tailwind 类名、`const tsa`/`wafEnabled` 标识符、中/日/法
  安全文章、带 Request-ID 的错误页、安全看板、防火墙营销页、隐私政策、JSON/GraphQL
  响应、CF Ray-ID 注释、CDN 页脚),断言:**任何样本都不得 `blocked`**(FN 关键属性)、
  **不含厂商名的样本不得指纹出厂商**。并带**变异对照**:把 Phase 294 之前的 hint 表
  原样放进测试,断言它会在 ≥10 个样本上误触发(证明这张网真能抓住旧问题,而不是
  恒真的空断言)。`tests/test_waf_benign_corpus.py` 4 例;与 294 合计 22 passed。

- **Phase 296(docs):Known limitations ⑤ 关闭** —— 291(指纹)/294(blocked 证据)/
  295(良性语料网)三轮 + 本轮 8 面复测后,⑤ 从"部分解决"改为**已解决**,复测口径
  (哪些面、期望值)写进条目本身,不再留"待复测"这种无判据的尾巴。

- **Phase 297:降级爬取进 HTML 报告——JSON 有字段不代表人看得见** —— 293 把
  `crawl_engine`/`crawl_fallback_reason` 写进了 JSON,但 HTML 交付物只字未提;
  而"降级爬取"直接改变"0 findings"的含义(浏览器 70-74 端点 vs 静态回退 18-22)。
  现在:降级时页面顶部出 `DEGRADED CRAWL` 横幅(含引擎与原因,并明示覆盖不完整);
  健康爬取在 meta 行显示 `Crawl: spa`;没开爬取则什么都不显示。
  测试 +3(健康/降级/无爬取三态),`test_crawl_fallback_visibility.py` 8 passed。

- **Phase 298:爬取宽度的第三个静默——"为什么停在这里"进报告** —— 293 修了
  "哪个引擎跑的",但**同引擎内**宽度仍可能不同,因为爬取有三种静默收尾:① 撞
  `max_total_pages` 时队列里剩下的页面**直接丢弃**;② 每页 8s 预算到点未达
  networkidle → 链提取可能不完整(`except: pass` 吞掉);③ `goto` 失败 → 跳过
  (仅 verbose print)。现在三者都计数并进报告:`crawl_stats`
  (`pages_crawled` / `pages_goto_failed` / `pages_budget_truncated` /
  `pages_dropped_by_cap` / `max_total_pages` / `per_page_budget_s`),JSON 与 HTML
  meta 行同时呈现(HTML: `Crawl: spa (12 pages, 1 failed, 3 truncated, 40 dropped (cap 50))`)。
  测试 +5(`tests/test_crawl_stats.py`,fake-Playwright 驱动真实爬取循环:撞帽丢弃/
  预算截断/goto 失败/干净爬取零问题/HTML 后缀);爬取+SPA 整组 **121 passed**。
  边界:Juice Shop 本轮不可用(并行会话的靶机崩溃),**同引擎宽度方差的真实靶复测
  仍待靶机恢复**;本轮交付的是"下一次可直接从报告读出原因"的能力。

- **Phase 299(测量):载荷语料审计 + blocked 丢载荷的账(结论:后者无需改)** ——
  ① **blocked 丢载荷**:量得 `_try_payload` 在 blocked 时是 `continue`(换下一个
  变形),**不是整批丢弃**;benchmark `pos-waf-01` 实测 9 次尝试中 4 次被拦,阶梯仍
  拿到 finding;无 WAF 对照 `pos-elem-01` 9 次 0 拦截。⇒ Phase 122 的病根是"放行被
  误判成拦截"(294 已修),此条**无代码可改**,记录在案。
  ② **语料 vs oracle 覆盖**:`payloads` 共 **2827** 条(分上下文 1192 条、40 个上下文
  + 36 polyglots);`python -m benchmark.corpus_gap` 报 825 条 token-覆盖、**2002 条
  含从未被判过的 token**(冷门 HTML5/SVG/MathML: `<span ontransitioncancel>`、
  `<address onbeforematch>`、`<dom-module>`、`<mfrac>` 等)。
  更关键的切片:**默认会发出的 427 条(40 上下文 × 前 14)里 168 条(39%)带未判
  token**——即这批载荷的沙箱裁定没有 Chromium 对照。按上下文:interaction_events/
  portswigger_events/html5_new 全部未判,math_context 12/14、data_uri 12/14、
  script_gadget 11/14、error_page 10/12、framework_react 10/14、header_reflection 9/14。
  **这是验证债,不是当前检出缺陷**(门禁 194/194 绿);是否扩 oracle 由成本决定:
  按"168 载荷 × 其本上下文"补测约 168 格,按全矩阵补则 ~3360 格。

- **Phase 300:补 168 格 oracle——抓到沙箱 3 个真误判(1 个 FN 源 + 1 个 FP 源)** ——
  按 299 的结论补测"默认会发出但从未被判过"的载荷:`benchmark/oracle_default_sent.py`
  对每个家族取最合适的 HTML 宿主(映射表显式),Chromium 双 sink(parser/innerHTML),
  产出 `benchmark/results/oracle_default_sent.json`(160 格,8 条因宿主无法建模而**列出跳过**,
  7 条载荷无 `alert(1)` 形式无法挂哨兵——都如实记账)。
  **结果:MISSED=4 → 0、OVER=1 → 0**,三轮修复:
  ① **`--!>` 是合法注释结束符**(WHATWG comment-end-bang)。tokenizer 只认 `-->`,
  `<!--` + `--!><svg/onload=...>` 被当成一个注释 → 越狱载荷判 inert,浏览器实际执行
  (html_comment 家族 ×2)。**这是 FN 源**。
  ② **`onerror="__x()//"` 能编译**。`_js_parses(wrapped=True)` 拼的是
  `function __h(){ __x()// }`,`//` 把闭合括号注释掉 → 误判语法错误。而
  `alert(1)//` 是**语料里最常见的收尾写法之一**(markdown + html5_new 家族,双 sink)。
  **这也是 FN 源**。修法:包装时闭合括号单独一行(浏览器编译事件处理器时正文尾部本就有换行)。
  ③ **MathML 命名空间的 `<script>` 不执行**。浏览器实测:`<math><script>` 与
  `<math><annotation encoding=text/html><script>` 都 inert,`<svg><script>` 执行,
  `<annotation-xml encoding=text/html>`(集成点)执行。沙箱不看命名空间 → 把
  `<math><annotation …><script>` 判 live。**这是 FP 源**。
  测试:新增 `tests/test_sandbox_phase300.py`(6 例,三处修复 + 反例)与
  `tests/test_oracle_default_sent.py`(对账网:MISSED/OVER 必须为 0,且断言产物非空;
  含"无反例即失败"的空断言防护)。sandbox/mxss/verifier/context 组 **178 passed**,
  主 oracle 对账 `test_sandbox_fidelity.py` **8 passed**。
  边界:家族→宿主是**尽力映射**(40 家族 vs 20 宿主),不做全矩阵;跳过与无哨兵的
  条目在产物里列明,不假装已判。

- **Phase 301:range7——独立技术栈的第四类靶场,首跑双引擎全绿,并抓到一处 context 字段分歧**:
  现有 range3–6 与 194 例基准都在本仓库内写就,扫描器可能悄悄拟合自己的靶场。range7
  刻意在**每一处表层**都不同:纯标准库 `http.server` + SQLite、表格布局、无框架;
  四个注入面各带"按构造安全"的双胞胎——引号属性值、`<script>` 配置行、存储评论线程、
  hash 路由 DOM sink(先 `decodeURIComponent`,Phase 265 的教训)。构造效度先做:
  `tests/test_range7_construct.py` 对**服务端字节**断言(vulnerable 面必须原样回显、
  safe 面必须转义/`\x3c` 编码、stored 面必须真有内容、两个 profile 只因 sink 不同)。
  **首跑**:sync **TP4/FP0/TN4/FN0**,async **TP3/FP0/TN3/SKIP2(存储用例仅 sync)**;
  `r7-pos-dom` 的阳性有浏览器执行证据(fired),门禁同 range4 标准(任何 FN/FP/ERROR
  或"阳性无浏览器证据"即失败)。
  **顺带量到一处字段语义分歧**:`r7-pos-attr` 上 sync 的 finding 报
  `context=html_attribute_dq`(反射分类上下文),async 报 `context=script_block`
  ——因为 async 用**验证器观察到的**上下文覆盖了分类结果(`context=v.get("context") or context`)。
  两者都是 TP,但同一字段在两引擎含义不同。**未在本轮修改**:需要决定"哪个定义对"
  (mXSS 场景里验证器上下文更有信息量),倾向**新增 `sink_context` 并列报告**而非替换;
  另立一轮。
  边界:range7 尚未接入 CI(`.github/workflows/ci.yml` 目前在并行会话的未提交改动里,
  不动它);`results.json` 已入库,可直接与后续轮次对比。

- **Phase 303:range7 扩到 12 用例(JSON 配置块 + 二跳),并先抓出自己两个构造错误** ——
  新增两个形态:`<script type=application/json>` 配置块 → `innerHTML`;以及**二跳**
  (POST `/settings` 存 → 另一个页面 `/admin` 渲染),各带安全双胞胎。
  **新增面第一跑就暴露两处"靶场自身的错"**(扫描器都是对的):
  ① `preview-safe` 用 `\u003c` 转义 `<` —— 字节上看着安全,但 `JSON.parse` 会把它还原
  成 `<`,紧接着就是 `innerHTML` ⇒ **页面仍然执行**,扫描器给出**带浏览器证据的 high**,
  被记成 FP。教训:**按 sink 转义,不按载体转义**。
  ② `/settings` 的 POST 只读 `text`/`comment`,没读 `name` ⇒ 注入被静默丢弃、视图为空,
  被记成 FN。
  两处都修,并把**构造效度升级为浏览器双向实测**:`tests/test_range7_construct_browser.py`
  用 Chromium 断言 **vulnerable 面必须执行、safe 面必须不执行**(12 例)。途中还修了探针
  自身的两个空断言:① `__x()` 写的是 **pathname** 不是 `'1'`(`_read_hit` 恒 False);
  ② `/widget` 面的可利用点是**关闭 script 元素**而非引号越狱(引号已被转义)。
  **评分口径**:`range7/runner.py` 显式排除**建议型 finding 族**(`csp_*`、`trusted_types_*`)
  —— 与 range3/4/6 已有的 `csp_*` 惯例一致:"没有 Trusted Types 策略"是关于页面的加固建议,
  不是"我们的输入进了 sink"的证据;不排除的话任何用 innerHTML 的页面都会变 FP。
  终局:**sync TP6/FP0/TN6/FN0(12/12)**,async **TP4/FP0/TN4/SKIP4**(存储与二跳按声明仅 sync)。
  边界:同前(CI 未接);`test_range7_construct_browser.py` 需要 Playwright,缺失时由既有
  conftest 规则处理;浏览器夹具用**独立线程 + 任务队列**,避免 Phase 200 的 loop 卡死
  污染后续测试(曾 12/12 全 skip)。

- **Phase 302:range7 抓到的 context 分歧已修——"一个字段一个含义",两引擎对齐** ——
  async 的 finding 构造里是 `context=v.get("context") or context`:**验证器观察到的
  sink 覆盖了分类得到的反射上下文**,于是同一反射 sync 报 `html_attribute_dq`、
  async 报 `script_block`(都是 TP,但字段含义随引擎变)。落法:**`context` 一律回到
  分类上下文(与 sync 同义)**,验证器那份**新增 `sink_context` 并列呈现**(8 处构造点),
  HTML 报告的 Context 列在两者不一致时追加 `→ <sink>`(一致时不显示,普通行零变化)。
  这两个字段**不参与载荷选择**(选择用的是局部变量 `context`),所以只改报告、不动检测。
  实测:range7 `r7-pos-attr` 现两引擎**都报 `html_attribute_dq`**,async 另带
  `sink_context=script_block`。
  测试:`tests/test_range7_parity.py` 4 例(双引擎 context 必须一致 / async 必须带
  独立 sink 值 / 报告只在不一致时显示);async 套件 123 passed(唯一失败
  `test_async_budget::…confirming_endpoint` 为已核实预存失败)。
  边界:`.github/workflows/ci.yml` 仍在并行会话手里,range7 暂未挂 CI;本轮改动经
  全量门禁复核。

### Added

- **`--login-json` / `--stored-relogin`:写入后重新登录,让"快照式视图"渲染新值(Phase 278)**:
  Phase 277 量出 `True-Client-IP` 的载荷能落库但视图不渲染,根因是 **JWT 在登录时把
  `lastLoginIp` 快照进去了**,`whoami` 返回旧值。补上三个开关:`--login-json`
  (凭据以 JSON 发送,从 `--login-token-path` 默认 `authentication.token` 取 token)、
  `--stored-relogin`(每次注入后重跑登录,把新 token 同时刷进 HTTP session 的
  `Authorization`、`auth_headers` 与浏览器的 localStorage,再渲染视图)。
  实现:`core/session.login_json()`(返回 headers/storage/token 三态)+
  `scan_stored_dom(relogin=...)`。
  **真实靶场实测(OWASP Juice Shop 20.2.0)**:重登录前该 token 在页面里**根本不存在**;
  重登录后 `stored_dom high/high`、sink `Element.innerHTML` @ `/#/privacy-security/last-login-ip`、
  40 请求 —— **视图侧闭环了**。
  诚实记账:扫描器自己的载荷(`<<script>Foo</script>iframe …`)在 DOM 里仍是**转义文本**,
  独立 Chromium dialog 监听 `dialogs []`;同端点换 `<iframe src="javascript:alert(123)">`
  则 `dialogs ['123']` ⇒ 应用侧成立、扫描器这条仍是"sink 到达"而非"执行"
  (与 Phase 276 同一条 caveat)。召回账记 **5/9**(检测到面),载荷执行问题另行决策。
  测试 20 passed(新增 5:login_json 三点 + relogin 接线两条);未改判定语义,
  按规矩补跑 64 例 strict 切片回归。

- **`--stored-header` / `--stored-method`:存储注入能写请求头、能发 GET(Phase 277)**:
  又两个"能力早就存在、CLI 没接"的真空档。`scan_stored` 只会把载荷放进 body/query,
  `scan_stored_dom` 还硬编码 POST 且完全忽略 `--stored-header`——所以
  `GET /rest/saveLoginIp` + `True-Client-IP` 这种**头写入**表面根本表达不了。
  现在两条路径都支持:`--stored-header NAME` 把载荷放进请求头(伴生字段仍进 POST body),
  `--stored-method GET|POST` 控制写入方法。测试 13 passed(新增 3:请求头、GET 不泄漏到
  query、DOM 路径不再忽略头参数)。
  **真实靶场实测(OWASP Juice Shop 20.2.0)**:`lastLoginIp` 被写成
  `<svg/onload=alert('xssv_c6db15af')>` —— 写入确实发生;但扫描仍 0 findings,
  原因是 **JWT 在登录时就把 `lastLoginIp` 快照进去了**,`whoami` 返回旧值,
  视图页不会渲染新写入的内容。手工补一次重新登录后,同一页面立即
  `dialogs ['123']`、DOM 里 `<dd><small><iframe src="javascript:alert(123)"></small></iframe></small></dd>`
  ⇒ 第 9 条(HTTP-Header XSS)在应用侧成立,扫描器缺的是**写入后重新认证**,
  不是写入能力。召回账仍 4/9,但 #9 的阻塞点从"头写不了"精确到"会话不刷新"。

- **`--stored-json`:HTTP 存储路径能发 JSON 体与伴生字段(Phase 274)**:`scan_stored(data_json=...)`
  从 Phase 241 就在,`--stored-extra` 从 Phase 152b 就在——但 CLI 两个都没接:前者没有开关,
  后者只在 `--stored-dom` 分支里解析。于是"JSON 写入 + JSON 视图"的真实接口只能靠
  `--stored-dom` 表达,而那会强制走浏览器渲染。现在 `--stored-json` 直接落
  `data_json=True`,`--stored-extra` 在两条存储路径上都生效:伴生字段与载荷进同一个文档,
  载荷始终占 `--stored-param`(不会被 extras 覆盖)。3 例纯逻辑测试锁线格式。
  **真实靶场实测(OWASP Juice Shop 20.2.0)**:`POST /api/Feedbacks`
  (`comment` + `rating` + `captchaId` + `captcha`,JSON)132 次写入全部 201,库里能看到
  真实载荷 `<iframe src="javascript:alert('xssv_…')">`(服务端 sanitize-html 放行了
  javascript: URL);`L4_stored` 层执行,但 `verify_semantic` 判
  `url_javascript / no executable node carries the token` ⇒ **HTTP 视图 0 findings 是正确
  负结果**——JSON 文本本身不是可执行文档。
  **Phase 275 修正了这条的范围**:同一个落库载荷,在登录后的 `/#/administration` SPA 视图里
  被浏览器臂判为 `stored_dom` high/high,并用真实 Chromium 的 dialog 监听复现了两次
  `alert('xssv_…')`。该轮缺的不是载荷,是**已登录的浏览器视图**。
  环境记一笔:本机 `python -m xsssentinel` 在子进程里偶发 `No module named xsssentinel`
  (同 cwd/env 下 `-c "import xssentinel"` 正常),改用
  `-c "from xssentinel.__main__ import main; sys.exit(main())"` 后稳定;与产品无关。

- **SPA hash 路由发现(Phase 209)**:`js_miner.spa_query_params()` /
  `hash_route_urls()` 从应用自己的 bundle 里配对
  `navigate([/route], {queryParams:{…}})` → 产出 `origin/#/route?param=x` 端点
  (上限 12),接线到三条发现路径(sync 静态爬虫、sync SPA 爬虫、async 爬虫);
  端点签名去重把 **fragment 纳入**(否则同 host+path 的 45 条路由塌成 1 条)。
  动因是真实靶场实测:OWASP Juice Shop 20.2.0 上 `-u <origin> -c` 得到 74 端点、
  **0 个带 fragment**,而手工给 `/#/search?q=apple --headless` 11.4s 即拿到
  browser-executed high —— 缺的是可发现性,不是检测能力。
- **真实应用外部效度驱动 `dev/juiceshop_external.py`**:起服 / 表面探针 /
  写面探针 / 扫描矩阵;ground truth 取上游 `challenges.yml`(9 XSS / 69 non-XSS)。
  Phase 200 记的"外部效度需要一个本仓不具备的驱动器"至此结案。
- 新门 35 例(逐文件 `--collect-only` 实测):`tests/test_phase209_template_control.py`(9)、
  `tests/test_phase209_spa_hash_routes.py`(17)、
  `tests/test_phase209_spa_route_delivery.py`(4,**双引擎** × 阳性/safe 孪生,
  真 Chromium + 变异对照)、`tests/test_phase209_accept_encoding.py`(5,含反向对照)。

- **SPA 路由进入 Agent 面与 `--discover`(Phase 210)**:`harvest()` 从渲染后的 DOM 收
  `a[href^="#/"]`,`_normalize_harvest` 新增 `routes`(**fragment 原样保留**,与
  `resource_urls` 相反 —— 剥掉 fragment 就退回 Phase 209 那个"把路由当服务端路径"的错);
  `xssentinel_discover` 的 payload 多一个 `spa_routes` 字段。扫描集按**可探测性排序**
  (fragment 带 query 的路由 > 同源端点 > 无参路由;后者仍返回,只是不占 10 槽预算),
  并让 `--discover` 复用爬取侧的 bundle 矿机,于是
  `xssentinel -u <origin> --discover --headless`(**不带 `-c`**)在真实靶上给出
  `dom_dynamic` high/high **browser-executed**(`#/search?q=`)。
  新增 12 例(纯函数 5 + 真浏览器 1 + 排序 5 + MCP 链 1)+ 排序规则变异对照
  (退回"路由一律靠前" → 5 例里 4 例红)。

### Fixed

- **反射了 marker 但拒原始标签的解码端点补上编码重试（Phase 307）**：Phase 306 的
  有界编码探针只挂在"未反射"分支；XSSMaze `realworld-encoding` 1–3 / `decode`
  3–4 是明文 marker 回显、原始标签被拒的兄弟形状，而变换梯子因 Phase 157 的
  token 守卫跳过所有会改写 token 的编码。现在载荷循环失败后再跑一次，形态扩到
  `base64` / `double_base64` / `double_url_encode` / `triple_url_encode` /
  `html_escape` / `fullwidth`（单载荷、至多 6 请求/参数），双引擎同门同预算。
  新增 `double_base64` / `html_escape`（`&#x27;` 形态，匹配 lab level3 的自定义
  双解码器）。真实 lab 双引擎五端点全部命中且 transform 与形态对应，27 条控制例
  0 findings；sync/async 全量 194 均 F1 1.000；strict 64 双引擎 FP0/FN0/ERROR0。
  同时修掉同函数两处不一致：编码探针未过滤 `--skip-param`，以及
  `BudgetExhausted`/`CircuitOpen` 被裸 `except` 吞掉。全量 1013 端点 server
  群体（干净 worktree HEAD 1580f8c，官方 runner）：**TP925/FN88/FP0，F1 0.955**；
  4 条 100s wrapper 超时单跑 10–12s 命中（补齐口径 929/84），27 控制例 0 findings。

- **解码回显型 XSS 的漏报与 async 的"严格解码"盲区(Phase 306)**:应用先解码再回显
  (base64 / 多轮 URL 解码)时明文 marker 不回显,而候选与变换梯子都以"已反射"为前提,
  该参数在早退分支就被放弃。新增**有界编码优先探针**(GET query + HTML、单个载荷 ×
  base64 / double / triple,至多 3 请求/参数),sync 与 async 同门同预算,证据走既有
  verifier 与 `_record`。定向 lab:sync 与 async **各命中 2 条**(`realworld-encoding-level4`、`decode-level1`),其余 6 条需要
  家族特定形状;27 条控制例 0 findings。外部 server 群体 **TP920 / FN93 / FP0**
  (F1 0.952,4348.9s;六条编码 FN 恢复,四条既有检出因超时/polyglot 摆动本轮未中)。
  同步修掉一个更深的 async 缺陷:aiohttp 的 `text()` 严格解码遇到非 UTF-8 响应体
  (lab 的 `/decode/level1` 对不可解码输入回裸二进制)会抛错,被 `_probe_param` 的裸
  `except` 吞成"该参数无反射" —— sync 的 requests 用 `errors="replace"` 所以一直能
  扫。共享 `_read_text()` 让 async 退回 `read()` + `errors="replace"`,并接到引擎全部
  文本读取点(能正常解码的响应路径不变)。sync 全量矩阵 TP113/FP0/TN81/FN0/ERR0
  (F1 1.000),async 全量矩阵 TP107/FP0/TN75/FN0/ERR0(F1 1.000);新增 7 例(含 `_read_text` 双向与二进制
  回显端到端,变异对照证明两处 L1 读取都在承重)。

  无代理复测时 range4 跑成 **8m58s / 2 个 ERROR**、range6 **3m44s / 1 个 ERROR**
  (每次卡住的用例还都不同),range5 却 49s 全绿 —— 同一个提交、同一台机器。
  `benchmark/runner.py` 从 Phase 69 起就有 `_evaluate_with_retries`(Phase 176n 又把
  触发条件从 "verdict==FN" 改成"这行没有信息"),四个靶场 runner 却一直单跑一次。
  照同一语义补进 `range_gate.py`:`invoke_with_retries` 只重试**没有回答**的行
  (无 report,或 `requests==0`),**绝不把结论重试掉** —— 两次都没有报告仍然是 ERROR,
  因为"没跑完"不是"正确地没发现"。重试次数落进行的 `retries` 字段并打印
  `(retried Nx)`,`recovered` 与 `clean first time` 保持可区分。只给 1 次而不是基准的
  2 次:靶场单例超时是 180s,两次重试会把一个楔死 case 变成九分钟的红墙。
  测试 33 例(新增 7):`unanswered` 五态、一次超时后恢复、两次都超时仍 ERROR、
  干净报告不重试、**AST 断言四个 runner 的 main 都调用它**、以及 range3 `main()` 的
  端到端重试(`retries==1` 且 exit 0)。
  诚实记账:本轮两次复跑 `retries` 全是 **0** —— 机器恰好没楔死,所以 range6 回到
  1m01、range4 sync 回到 1m52 **不能记在重试头上**;重试本身由确定性假实现验证。
  另:关掉代理并不让这些靶场变快或变慢,楔死的成因是负载,不是代理。

- **外部效度复测被本机出口代理污染,差一步记成产品缺陷(Phase 268)**:shell 里
  `HTTP(S)_PROXY=http://127.0.0.1:4958` 时,扫描器取 Juice Shop 的 bundle 第一次正常
  (`main.js` 1.21 MB),随后 `polyfills.js`/`scripts.js` 拿回的都是 **9608 字节的
  index.html**,于是 `_js_hash_routes` 返回 **0 条**,`-u <root> -c` 得到 0 findings。
  这条链路看起来完全像"SPA 路由发现失效",实际是**测量通道被代理改写**。
  同一条链路加 `NO_PROXY=127.0.0.1,localhost`(以 `--crawl-depth 1` 取证,避开 depth 2 的
  楔死):三个 bundle 全部正常、**5 条 hash 路由**
  (`#/search`、`#/login`、`#/address/select`、`#/track-result`、`#/chatbot`)、
  **1 条 `dom_dynamic` high/high browser-executed @ `#/track-result?id=xss`**
  (22 端点,77s,`headless.outcome=fired`)。结论:外部效度成立,先前那个 0 是假阴性。
  驱动同步修两处:`XS_JUICE_BUNDLE` 可指向任意完整的 20.2.0 树(仓库自带副本的
  `build/`+`node_modules/` 已被 2026-10 的工作区清空移除);缺 `build/` 时 **1 秒内**
  报出原因,而不是健康轮询 90 秒后只说 "never became healthy"。docstring 写入
  NO_PROXY 要求与本次实测数字。
  附一条诚实记账:无代理的 `--crawl-depth 2` 跑 25 分钟仍 0 连接(Phase 219 记过的
  同形楔死),已停止,改用 depth 1 取证;它不是产品结论,也不当作通过。

- **靶场门禁看不见"浏览器到底跑没跑"(Phase 267,与 266 同族)**:range4/range5 每个正例都
  打印 `browser-confirmed=N`,门禁却只检查 TP/FP/TN/FN。实测:把
  `PLAYWRIGHT_BROWSERS_PATH` 指向空目录(等价于没装 Chromium),两个正例仍是 **TP**、
  `browser-confirmed=0`、`headless.outcome=errored`,门禁照打 "every case scored as
  ground truth requires"、**exit 0** —— 靶场存在的唯一理由(真实浏览器执行)整场没发生,
  而门是绿的。修法:规则收进 `range_gate.py` 单一实现(`failing_rows` + `evidence_gaps`),
  range3/4/5 三个 runner 调用;manifest 声明 `headless: true` 的正例必须至少有一条
  `fired`,否则 exit 1。**同一实验修复后 exit 1**;正常面:range5 双引擎 exit 0、
  range4 sync 单独 exit 0(`browser-confirmed=12`)、range3 async exit 0
  (`r3-pos-utf7` confirmed=11)。range3 的 utf7 用例同样声明 headless,一并纳入
  (它此前根本不记录 confirmed)。测试 `tests/test_range_gate.py` 13 例(含
  **AST 调用点断言**——函数体不会腐化,main 会不会继续调它才会)+
  `tests/test_range3_gate.py` 6 例("无浏览器证据 ⇒ 红")。
  诚实记账:本轮在负载高的机器上跑到过环境性超时(range4 sync 一个正例 180s、
  range3 async 每次一个不同负例 120s),单独复跑均 exit 0,不是本改动的行为;
  门禁把超时报成 ERROR 而不是 pass,正是它该做的。

- **range3 的 runner 永远返回 0,所以它从没被当成门禁(Phase 266)**:`main()` 打完
  TP/FP/TN/FN 表就 `return 0`,无论有没有 FN/FP/ERROR —— 这正是它出现在 Phase 223
  的"每道靶场都跑了"表格里、却没有任何 CI 步骤跑它的原因:**能跑不等于能拦**。
  现在与 range4/5/6 同一口径(FN/FP/ERROR ⇒ exit 1);manifest 声明的两例 sync-only
  (`r3-pos-stored`、`r3-pos-so2`)记 SKIP,不计失败——诚实声明不该被算成缺陷。
  挂进 CI(tests job,Range #2 与 #4 之间),产物 `range3/results_ci.json` 留档。
  新增 `tests/test_range3_gate.py` 5 例锁退出码契约:全绿 ⇒ 0、FN ⇒ 1、FP ⇒ 1、
  ERROR ⇒ 1,并显式断言 async 的 2 个 SKIP 不让门变红。HEAD(`4c53a4a`)实测
  sync TP20/FP0/TN6/FN0 · async TP18/FP0/TN6/FN0/SKIP2,**exit 0**。
  测试按路径加载 runner 后还原 `sys.path` 与 `sys.modules["server"]`:它插自己的
  目录到 `sys.path[0]` 是当脚本跑时的正确行为,但在整套 pytest 里会把
  `range3/server.py` 留成全局 `server`,污染之后收集的每个测试。

- **SVG 向量不再把兄弟 `<script>` 算成 SVG XSS(Phase 251,真 FP)**:`/fuzz/render`
  的 FP 臂抓到 2 例——反射已死(转义后)而页面带 `<svg>`+`<script>`(script 在
  `<svg>` 闭合**之后**)时,`svg_xss_svg_script` 照报 medium/high。根因在语料
  `xssentinel/data/svg_xss.json`:`<svg[^>]*>[\s\S]*?<script` 的 `[\s\S]*?`
  跨越了 `</svg>`。SVG 里的 `<script>` 只在 SVG 命名空间内执行,故 10 处跨越式
  pattern 改为"不得跨过自身闭合标签"的温和点;嵌套仍命中(不引 FN)、兄弟节点
  不再命中。发现手段:`dev/fn_net.py` 补上 **FP 臂**(验证器拒绝时也扫描——
  此前只记 neutralised 就跳过)与 **sink 维度**(端点参数 Phase 129 就有,网从未
  串上),198 组合首轮 covered=122/FN 0/FP 候选 33,逐 finding 回验后 3 真 FP。

- **TT 层"sanitizer 介导"流的两条 medium 无证据(Phase 225 续,range6 的第三条红因)**:
  `trusted_types_taint_flow`(层内注释自称 "concrete DOM-XSS finding")与
  `trusted_types_no_policy`("trivially exploitable")在 canonical 正确用法
  (当前版 sanitizer + innerHTML)的页面上照发 medium,而该页载荷被证明剥净
  (无活元素、无弹窗)。项目曾两次用变绕开这个形状(`m_sanitizer_safe` 用
  textContent;Phase 128b 用 DOMParser)——变绕正是它一直隐形的原因。现按证据分级:
  **识别到的 sanitizer 位于 source→sink 之间时**,flow 仍报(写入依然无 TT 保护,
  这是本层的本职)但降为 **low** 并在 title 点名 sanitizer;`policy.createHTML`
  仍整个丢弃 flow(不变,那才是 TT 的缓解);任一未介导的流存在 ⇒ 维持原级。
  顺带修掉新测试抓出的归因弱点:taint 源从"窗口内第一个"改为"离 sink 最近"
  (相邻语句的 `sanitize()` 曾会把另一条 raw 写入的流误标为介导)。sanitizer 词汇
  从 sanitizer 层导入,一处定义(Phase 207)。测试
  `tests/test_tt_sanitizer_mediation.py` 8 例,两条反证各验证。

- **净化器 mXSS 提示按证据分级(Phase 225)**:`sanitizer_output_to_innerhtml`
  此前对任何 `sanitize() -> innerHTML` 流**无条件**发 medium。于是"当前版 +
  正确用法"的页面会拿到一条 medium 的 "mXSS risk" —— 而该页上 CVE-2020-26870
  的载荷被证明剥得干干净净(无活元素、无弹窗,见新靶场 range6)。项目自己早就
  知道这个盲区并用变绕开了:`benchmark/server.py` 的 `m_sanitizer_safe` 注释原话
  是 "(The layer flags any sanitise->innerHTML flow, so changing only the
  version would still report.)",于是 negative 孪生被迫改用 textContent ——
  **canonical 正确用法(当前版 + sanitize→innerHTML)从来没有任何负面用例覆盖**。
  现在按证据分级:页面识别出的版本存在且**没有一个落在脆弱区间** ⇒ 降为 low 并在
  title 写明依据;版本未知或存在脆弱版本 ⇒ 维持 medium(先例:Phase 179 JSON
  反射 severity 连 confidence 一起降)。识别到的版本另在 `detected_versions` 回报。

- **共享 Chromium 崩溃后全进程静默丢失 DOM 确认(Phase 224)**:`get_shared_browser()`
  发现线程本地的 browser 已死(崩溃/被 OOM kill/主机压力)时,旧代码直接走重启路径,
  而那个死实例的 playwright 同步 API 已把 greenlet loop 停泊在本线程 ——
  `_loop_running()` 守卫于是对**后续每一次**启动抛 `RuntimeError`,
  `analyze()`/`harvest()`/`verify_headless()` 的裸 `except` 再把它吞成空结果:
  浏览器一旦死掉,本进程余下所有动态 DOM 确认静默变零(最坏的静默 FN 方向)。
  实测形态:13 小时全量套件里 `test_range5` 的实时 Lit 对败在
  `all findings: []`;`dev/_stale_browser_probe.py` 可确定性复现。
  现改为**先展开失活实例再重启**(`shutdown_thread_browser()` 会把旧 loop 停出道路,
  真浏览器端到端验证自愈成功),同时 `analyze()`/`harvest()` 的吞异常 except 补
  `_log.warning`(点名 URL 与异常)——"没有 finding"与"没有浏览器"从此在日志里
  不再同形。门:`tests/test_shared_browser_recovery.py`(3 例,含反向守卫:
  健康实例必须原样复用、绝不碰 `pw.stop()`;两条反证各验过)。
- **两个全量套件顺序依赖 flake 的测试侧(Phase 224)**:①
  `test_range5` 实时浏览器对在浏览器确实不可用时带原因 **skip**,不再报
  "无 browser-executed finding"(safe 孪生同理——没浏览器时它原是**假绿**);
  ② `test_passive_proxy::test_oversized_body_refused_413` 的 2.1 MB 传输预算
  15s→60s(13h 套件实测本机 ~20× 劣化,2 MB loopback 传输超过 15s,客户端收到
  `b''` 致走私安全断言败于环境),空响应时给出区分"主机劣化/代理从未应答"的
  诊断信息;断言本身一字未动。

- **`template_ssti_*` critical 假阳性(Phase 209)**:`detect_rendered()` 原为
  `"49" in response_text`。靶场把 `{{7*7}}` **原样回显**(无模板引擎),而 406
  错误页唯一的 `49` 是栈行号 `route.js:149:13`,于是发出 critical 发现且 evidence
  声称"rendered to 49"。现加**差分对照请求**(同参数发无数字值),并对该层
  直接 `append(Finding(...))` 缺失的 `confidence` 键补上(与 Phase 198 的
  polyglot 同类元数据缺陷),evidence 改为描述实测。
- **async 爬到即检查(Phase 209)**:`_crawl_and_scan` 对带 fragment 的端点改跑
  `_scan_dom_async` 并纳入去重(此前只跑反射层,而 fragment 参数只有浏览器读得到;
  `split("?")` 还会切掉 fragment 内的 query)。复测:`--async -u <origin> -c
  --headless` 在真实靶上给出 high/high browser-executed(`#/track-result?id=`,
  与 sync 的 `#/search?q=` 是两个不同 sink,均经独立 Playwright 复核为 parsed)。

- **async 只声明可解码的压缩(Phase 209)**:`safe_accept_encoding()` 实测
  aiohttp 自己的解码路径能否往返,再决定 `Accept-Encoding`;操作者显式设置不覆盖。
  修的是 `--async` 对整个真实靶场失效:`HAS_BROTLI=True` 于是声明 `br`,而解码器
  以 `process(data, max_length)` 调用只实现 `process(data)` 的 `Brotli` 包 →
  每个响应 `400 Can not decode content-encoding: br`(实测 374 请求 / 0 结果)。

- **文档种类进入判定(Phase 210b)**:新增 `xssentinel/core/document_kind.py` ——
  媒体类型优先、URL 后缀兜底(`.js` 答 `text/html` 判为页面而不是脚本)。
  两条页面形态判定按**证据能支撑到哪一档**各改各的:
  `trusted_types_no_policy` 在脚本资源上不再发出(它读的是**页面**的 CSP 头,
  脚本响应没有 → 对地球上每个 `.js` 恒真);`framework_*_xss` 在脚本上降为
  low/low 并在 evidence 里写明 "JavaScript resource (no page context)"
  (模式是真的:Juice Shop 的 chunk 确实调 `bypassSecurityTrustHtml()` ——
  留线索、撤音量)。接线在双引擎唯一的页面层入口 `run_page_layers()`,
  复用 CSP 判定已经要发的那次请求,**零额外请求、两引擎不可能不同步**。

- **静态层"自己给自己作证"(Phase 210b,`docs/OPTIMIZATION.md` 1.5 结案三类病因)**:
  ① `postmessage_xss` / `websocket_xss` 的判定谓词用
  `setTimeout\(\s*[^,)]*[a-zA-Z]` 声称"字符串实参",而该模式**同样命中传函数的正常形状**
  (真实靶 `main.js`:37 处 `setTimeout(` 全是函数,`addEventListener('message'` 出现 0 次,
  仍报两条 high)。改为共享谓词 `core/string_eval_sinks.py`(先认回调形状,再认字符串/拼接/`data`;
  裸标识符**故意不判**并钉成测试)。
  ② `open_redirect_xss` 是 Phase 113b 的**没修完**:113b 只遮了赋值式的左手边,
  调用式 `window.location.replace(` 没有左手边,而 `USER_INPUT_RE` 含 `window.location`
  → sink 自己算作用户输入;且固定 200 字符尾窗**伸进下一条语句**,压缩包里下一条通常又是
  同一个 sink → 邻居替它作证。现遮罩含 `window./self./globalThis.` 限定符、遮罩窗口内
  **全部** sink 跨度,并把判定区收窄为该 sink 自己的语句(调用式到配对右括号,赋值式到 `;`);
  RHS 完整保留 —— 模式里的 `[^;\n]` 会吃掉 `location.hash` 的首字母,整段遮罩会误杀真阳。
  **bundle 级取证**:同一批 28 个真实 JS 文档双臂(HEAD 模块 vs 现模块)对照,
  HEAD 6 条 exploitable → 现 0 条,真阳 fixture 两臂都报,且逐条打印被删项供归因。
  ③ 上面那条页面形态判定(文档种类)。
- 新门 **29 例**(`29 passed in 0.41s`)+ dispatch 契约门:
  `tests/test_phase210_string_eval_sinks.py`(9)、
  `tests/test_phase210_redirect_selfsource.py`(10,含样本表 ↔ `DANGER_SINKS` 双向覆盖,
  与 `_mask_span` 切片偏移断言)、
  `tests/test_phase210b_script_documents.py`(10,含用 AST 读 `run_page_layers` 的每条
  `run_layer(...)` 实参并 `inspect.signature().bind()` 核对 —— 防"层签名漂移被
  per-layer guard 吞成 DEBUG",本仓在 Phase 63/84/198 三次同一形状;
  以及**穿过 dispatch** 的一例)。
  变异对照 `dev/phase210b_mutation_control.py` **两次跑都报过 `guard_is_load_bearing=False`**:
  M1 锚点落在 `_statement_end()` 的赋值式分支(真实靶走调用式分支),M2 揭示
  "邻居落进 60 字符前瞻窗口"这个形状没被样本覆盖;M5(把 `content_type` 的读取打回
  大小写敏感)揭示**测试自己用了带 `.js` 后缀的 URL**,兜底规则替 bug 说话 →
  换成无扩展名路径后才有区分力。顺带据此修了一个真缺陷:`_hdrs` 是从
  CaseInsensitiveDict 复制来的普通 dict,现按 `k.lower()=="content-type"` 取。
  五项最终全部 `mutated_red=True / restored_green=True` + 逐字节还原自校验。

### Verified

- **真实靶复测(OWASP Juice Shop 20.2.0,同一目标版本、同一命令)**:
  `dev/_js_out/findings_p210b_discover.json` —— `-u <origin> -c --discover --headless`
  给出 **1 条** finding:`dom_dynamic` high/high **browser-executed**(`#/track-result?id=xss`),
  而 coverage 里 **4 个 JS 文档在扫描集内**(`main.js` `scripts.js` `polyfills.js`
  `rolldown-runtime-*.js`)却**一条不发** —— 对照改前同一 arm 的
  `findings_discoveronly3.json`(3 条 high + 2 条 medium 全落在 `.js` 上)。
  **两条引擎各自打同一个 bundle**:`p210b_mainjs.json` sync 52 请求 / **0 findings**、
  `p210b_mainjs_async.json` async 27 请求 / **0 findings**(改前该 URL 给 3 条 high)。
  靶的 `Content-Type` 实测为 `application/javascript; charset=UTF-8` ——
  即起作用的规则是**媒体类型**那一条,不是 URL 后缀兜底。
  注:该轮 `scan_status=partial`(14898 attempted / 8 failed),成因是靶进程
  **JS heap OOM 崩溃**(node 死在扫描中途,日志 `dev/_js_out/juiceshop.log`),
  属目标侧资源不足而非扫描器缺陷 —— 复测的单 URL 两臂均在健康靶上跑完。
- **精度门全复跑(降档改的是 severity,而打分器按 severity 过滤 —— `runner.py:329`
  只把 high/medium/critical 算作"检出",所以必须复跑全量而不是切片)**:
  64 例 strict 切片双引擎 sync **TP36/FP0/TN28/FN0/ERR0**、async
  **TP36/FP0/TN27/FN0/ERR0(1 SKIP)**,f1 均 1.000;全量 192 例 **sync
  TP113/FP0/TN79/FN0/ERR0 f1=1.000(902.9s)**、**async TP108/FP0/TN74/FN0/ERR0
  (10 SKIP)f1=1.000(786.7s)**,逐项等于既有基线。
  **诚实归因**:async 全量臂跑在同一 worktree 的并发会话正改 async polyglot 降档的期间
  (`async_scanner*.py`,属 Phase 208 那条 /r/url03 分歧的修复,不是本轮),
  该读数证的是"两件事叠加后仍零退化",不是"只有本轮改动为零退化";
  本轮改动的单独凭证是 sync 全量臂、双引擎切片与真实靶两臂
  (`benchmark/results/phase210b_{quick_sync,quick_async,full_sync,full_async}.json`)。
- 全量 192 例矩阵**双引擎**复测零退化(切片绿灯不等于全量没变):
  sync TP113/FP0/TN79/FN0/ERR0、async TP108/FP0/TN74/FN0/ERR0(10 例 SKIP 为
  manifest 声明 sync-only 的 stored/二阶),两引擎 f1 均 1.000;
  64 例 strict 切片亦 FP0/FN0/ERROR0。
- `--self-test` **ALL CHECKS PASSED**(93 PASS/0 FAIL),其中
  `L7 Template SSTI -> XSS fired (1)` 证明新加的差分对照杀掉假阳性但没杀掉真阳性。
- 真实靶场:range2 26/26(TP20/FN0/TN6/FP0)、range3 sync TP20/FP0/TN6/FN0 +
  async TP18/FP0/TN6/FN0/SKIP2、range4 双引擎 TP2/FP0/TN2/FN0 且 gate exit 0。
- 全量分批门禁 182/182 文件绿(2644s,failures: none);跳过口径按"绿≠跑过"一并给出:
  14 例 / 7 文件,其中 5 例是声明式跳过(`XSS_DOM_LIVE` opt-in 4 + POSIX 权限位 1),
  其余 9 例为负载诱发(抽跑 3 个文件即 `22 passed, 0 skipped`)。
- 同类竞品同靶对照在**冻结树**上重跑(`engine_stable=True`):60 例切片我方
  **f1 0.9859 / FP0**(复跑去掉一次性 ERR 后),dalfox v2.13.0 0.8254(FP1),
  nuclei v3.9.0 0.8387(25.2s);唯一 FN 仍是打分口径下的 `pos-xs-01`(XS-Leaks)。

- **全量分批门禁(`tests/run_all_batched.py`)本轮未跑 —— 按"未验证"记账。**
  跑前读进程表:同机 `D:\qoder\vuln-agent` 的 lab matrix/dvwa/scan 与本 worktree 另一会话的
  `benchmark/runner.py` 都在运行,即 Phase 187/200/201 三次记录过的同一形态。
  替代面(实测):新门 29 例 + redirect/DOM-源/客户端层 26 例 + layer-guard/TT/框架族 64 例
  + async 接线/层注册/coverage 奇偶 16 例 + **全部引用 `run_page_layers` 的测试文件
  118 passed in 14.11s**。

### Known limitations

- **[已解决 · Phase 218] 两条通用证据规则已立**:`docs/OPTIMIZATION.md` 1.5 的两条一般规则
  落地为 `findings.cap_unverified_severity()` —— "无浏览器证据(browser-executed / OOB /
  headless confirmed)、且无可核对 proof 的 `high`/`critical` 降为 `medium`"。
  **severity-only**:confidence 不动,评分分母不动(medium 仍算检出)。
  接线在双引擎的**最终出口**(sync `_add`;async `scan()` 的 yield 前、headless 复核之后),
  就地修改同一对象。驻留 population 是静态分析提示(trusted_types / policy_bypass 族),
  两引擎对称(Phase 217)。
  **未采用"硬拒绝"**:把不可核对的高危直接丢弃会把已检出的行变成 FN(评分口径里
  medium 算检出、丢弃不算),降档已消除"不可核对的高危",故按测量结论选降档。

- **[部分解决] DOM finding 的参数名**:真实靶上 browser-executed 的 `dom_dynamic`
  现在带 `param=q@hash`(Juice Shop 20.2.0,Phase 288/289 实测);**无参页面**的
  DOM sink 仍是 `param=None` —— 那种页面没有参数可命名,None 是诚实的。
  前提不变:fragment 投递服务端永远收不到,PoC 里自动导航的 HTML 才是正确重放。

- **[已解决 · Phase 214–216;Phase 290 实测复核] async 爬取页面的层覆盖**:
  爬到的非 fragment 端点现在跑全套页面层,与 sync 对齐。实测:同一"首页→DOM sink 页"
  爬取夹具上,双引擎产出**逐项相同**的 4 条 finding(含 evidence_class)。

- **[已解决 · Phase 291/294/295] 真实靶上的 WAF 误检**:两条指纹规则(裸 `ace-`、
  裸 `tsa`)在 291 收紧;294 又量到更严重的一层——`_BLOCK_BODY_HINTS` 里的**厂商名与
  主题词**(`cloudflare`/`waf`/`firewall`/`request id`/中文 `攻击`/`防火墙`…)与过宽的
  状态码集合(401/404/400/500/502)会把普通页面判成"被拦",而 `blocked` 会**丢弃载荷**
  ⇒ 静默 FN(CF 前置站的**放行** 200 响应也在其中)。
  **复测**:Juice Shop 8 个面(索引/搜索/API/401/404/未知路由/注入查询)全部
  `waf=None`、`blocked=False`、无 hint 命中;`Generic/Unknown` 未再出现;
  benchmark `pos-waf-01` 仍检出、`neg-waf-01` 仍无;295 的 20 样本良性语料网
  (含变异对照)持续守护这条边界。

- **[开放] 真实靶场上浏览器爬取宽度不稳定**(实测同命令 18 / 22 / 70 / 70 / 70 / 74 端点)。

## [1.2.1] - 2026-10-25

判定顺序与诚实性收口:case 归一化反射、async 主循环确认顺序、逐参数覆盖列,
以及三个跨引擎/外部靶实测台账。外部靶 XSSMaze server 复扫补齐口径
**932/81/0(R 92.0% / F1 0.958)**,控制例保持 0 FP。

### Fixed

- **case 归一化反射不再被判"未反射"(Phase 308)**:两引擎的反射判定从
  `marker in text` 精确匹配改为 `context.find_reflected_marker()`(先精确、
  再 ASCII-only 大小写不敏感,返回反射后的真实拼写);swap-case 服务器另有
  单载荷重试(`swap_case` 变换,sync/async 同门)。XSSMaze `casemanip` 家族
  3 条 FN 全部转正。
- **async 主循环的确认顺序对齐 sync(Phase 309)**:per-payload 的
  `build_polyglot` 附加探针会在上下文专属载荷之前确认并短路队列,五个
  benchmark 阳性例因此以 `polyglot_reflection` 记 FN;该味改为整个候选队列
  之后一次性发射。对等门扩到 17 端点(含 crawl 对)后 158 直达用例台账
  **0 分歧**。
- **--async 报告的逐参数覆盖列不再显示假零(Phase 310/311)**:
  `reflected`/`context`/`payloads_sent`/`confirmed` 接线,`payload_classes`
  记录每个派发载荷的真实语料族(tagged 采样器;派生载荷按设计记分类上下
  文)。此前任何 --async 报告读作 "0 payloads sent / reflected=False"。
- **预算传播测试契约随 309 更新**:`test_async_budget_propagation` 的
  confidence 断言原先钉的是被移除的 per-payload polyglot 评分。

### Added

- `context.find_reflected_marker()`、`swap_case` 变换、双引擎
  `_try_case_swap`、`cross_context_candidates_tagged` 采样器。
- **证据形状不变量门(Phase 312)**:high/critical 必须携带可查凭据
  (browser-executed / OOB / headless 已确认 / proof / evidence 五者其一),
  常驻门带帽变异对照(帽关掉实测咬出 4 条),211 路由全量 sweep 账本
  `benchmark/results/phase312_evidence_shapes.json`:164 条 high **0 违规**。
- **全量 parity 台账(Phase 313)**:158 直达用例 × 双引擎原始报告三元组,
  `phase313_parity_ledger.json`:**0 分歧**。
- XSSMaze 剩余 FN 重新归因(Phase 314,`dev/_xssmaze/`
  `FN_ATTRIBUTION_20261025.md`):delivery 切分 query 46 / 其他 35;唯一产品
  缺口 = HPP 首现位顺序;两条 dialog 模型结构性 FN(外链脚本 / 大写 JS)
  经 Chromium 实测定性。

### Verified

- XSSMaze v0.3.0 官方 runner 复扫(干净 worktree):server **TP931/FN82/FP0**
  in-run,补齐 1 条 wrapper 超时后 **932/81/0**(P 1.000 / R 0.920 /
  F1 0.958,4149s);27 条控制例 **0 FP**。与 1.2.0 的 929/84 相比 +3 全部
  来自 casemanip(投射逐条命中)。
- 内部 194 例矩阵双引擎 **F1=1.000**:sync TP113/FP0/TN81/FN0/ERR0,
  async TP107/FP0/TN75/FN0/ERR0;quick 严格切片双引擎 F1=1.0。
- 全量文件级套件 **169/170 绿**;唯一红是 309 的测试契约漂移(非产品回归),
  修复后复跑 7/7。
- 受影响面定点批与 ruff 全过;变异对照(310/312)实测咬合。
- `--self-test` **ALL CHECKS PASSED**(rc=0,~13 分钟)。

### Known limitations

- server 81 条实测 FN 的族分解与可修估算见 FN_ATTRIBUTION_20261025:语料可修
  ~16-20,产品缺口 1(HPP 首现位),结构性 2,DOM 通道 5,其余为逐上下文
  长尾;语料批次须遵守 instrument-first 协议(梯子预算已满)。
- 非 query delivery(25 body / 6 header / 4 path)受官方 runner 的 URL-only
  投递契约限制,不构成能力结论。
## [1.2.0] - 2026-10-23

外部靶场 XSSMaze v0.3.0 全量验证后的修复与发布收口。控制例假阳性从 13 降到 0,
双引擎在 194 例内部矩阵与第三方官方 scorecard 上均为 FP0。

### Fixed

- **补回 wipe 丢失的 `setHTMLUnsafe` sink 覆盖**:2026-10-16 加入但从未提交的
  `Element/ShadowRoot.setHTMLUnsafe` 与 `Document.parseHTMLUnsafe` 仪器在
  2026-10 工作区 wipe 后消失,client 群 `htmlunsafe-level1/5` 变为 0 findings。
  恢复后六级全部拿到 browser-executed 证据,client 群回到 TP24/FN0。
- **redirect landing 门**:302 落到另一路径且丢掉注入参数时,页面级静态提示
  (framework/Trusted Types/WebSocket/静态 DOM)不再归属被扫 URL。4 条
  redirect 控制例各 6 findings → 0;保留 query 的跳转不受影响。
- **CSP no-execution 门**:当强制 CSP 封死页面实际携带的全部脚本路由
  (无外链脚本、无 nonce/hash、无 bypass)时,mutation/DOM-clobber/静态 DOM/
  页面 hint 不再发射。3 条 CSP 控制例 3/3/8 → 0;`pos-csp-01/02` 与
  `neg-csp-*` 行为不变。
- **模板 SSTI 的 nonce 碰撞**:渲染值必须是独立 token(十六进制边界),随机
  nonce 里的 `49` 不再骗过差分产生 critical 假阳性。10 次重复扫描零
  template finding,12 条模板类阳性全部保留。
- **URL 属性 hint 标签感知**:`iframe/frame/embed/object` 的 `.src` 保留
  medium(真阳性 `dom-level18`),`img/media` 与无页面上下文的 JS 降为 low
  (`dom-level10` 控制例)。此前的无差别降档曾把 dom18 打成确定性 FN。
- **低噪声抑制**:数据型媒体(`application/json`、`text/plain`、`+json`)上的
  低档反射/polyglot 与 low 静态 DOM hint 不再发射;`application/javascript`
  (JSONP)与 `text/xml` 保留——`callback-level1` 与 `ctype-level1` 是仅靠
  low 反射成立的真阳性。`pos-jsonct-01` 更名 `neg-jsonct-raw-01`(safe),
  Phase 176g 的“保留 low 报告”契约被本版本取代;parity gate 的 incident-2
  变异仍可复现(sync 静默 / async 强制 high)。

### Added

- `core/page_relevance.py`(redirect landing 判定)、
  `csp.script_execution_blocked()`、`document_kind.is_data_only_media_type()`、
  `dom` 的 id→tag URL 属性分级。
- `tests/test_htmlunsafe_sinks.py`、`test_redirect_landing_gate.py`、
  `test_csp_no_exec_gate.py`、`test_url_property_sink_hint.py`、
  `test_low_noise_suppression.py`。

### Verified

- XSSMaze v0.3.0(官方 runner,ground truth 来自靶自身):client
  **TP24/FN0/FP0**(P/R/F1 1.000,418s),server **TP918/FN95/FP0**
  (P 1.000 / R 0.906 / F1 0.951,4195s);27 条控制例 **0 FP**。
  口径:对照例上的任何 finding 记 FP,population 上的 low finding 也计检出。
- 内部 194 例矩阵双引擎 **F1=1.000**:sync TP113/FP0/TN81/FN0/ERR0(858s),
  async TP107/FP0/TN75/FN0/ERR0(756s);async SKIP12 为 manifest 声明的
  sync-only(stored/upload/second-order/scenario)。
- 全量文件级套件 **229/229 绿(4787s,failures none)**;14 例/6 文件跳过,
  其中 opt-in 的 stored E2E(3 passed)与 DOM live(单跑通过)已显式复跑,
  `benchmark_fp` 单跑 94 passed。
- range4/5/6 双引擎门禁全绿(range4 TP2/FP0/TN2/FN0、range5 与 range6
  TP1/FP0/TN1/FN0);range6 首跑在起靶健康检查处读超时,重试绿。
- 全仓 `ruff check .` 通过;`python -m build --wheel` 与 CLI 烟测通过。
- `--self-test` **ALL CHECKS PASSED**(93 项);crawler 对 `/dom` 的发现检查已
  适配 Phase 265 的 `dom_sink_reachability` 投递证据,浏览器执行仍由 L6 独立断言。

### Known limitations

- server 95 条 FN:query 能力缺口 + 官方 runner 只给 URL 的 body/header/path
  投递契约形状;`stream-level1` 有一次 100s wrapper 超时。
- Phase 218 证据帽在非 CSP 页仍按 `proof/evidence` 豁免;TT 层对 `.src`
  有一次未复现的 medium 抖动;polyglot 确认存在运行间摆动(server TP 919/921/918)。

## [1.1.0] - 2026-10-09

Unreleased 段自 1.0.0(2026-09-29)起累积了 Phase 185–207 共二十余轮工作,
本版一次性收口。全部为新增能力与内部重构,**无对外 API 破坏性变更**
(`--sitemap` / `--skip-param` / `--wayback` / `--gql` / MCP 工具面均为新增;
语义变化只有一处:JSON 反射的 severity 现与 confidence 一同降级,
避免 severity-only 的消费者误判 —— 见 Phase 179)。

自编 192 例矩阵双引擎满分的口径不变:sync TP113/FP0/TN79/FN0、async
TP108/FP0/TN74/FN0,f1 均为 1.000;外部效度首次量出同靶三工具对照
(XSSentinel f1 0.986 / dalfox 0.825 / nuclei-dast 0.839,60 例分层切片),
其三条限定(我方唯一 FN 是打分口径而非判定错误、靶仍由我方构造、nuclei 用
49s 拿 0.839 而我方用 346s 拿 0.986)随该条目一并阅读。

### Added

- **DOMParser 重建链检测**(Phase 185):`DOMParser.parseFromString` /
  `importNode` / `adoptNode` / `cloneNode` / `appendChild` / `insertBefore` /
  `replaceChild` / `append` / `prepend` / `after` / `before` / `replaceWith`
  此前在 `dom_engine.py` 与 `sink_matrix.py` 里零匹配 —— "净化器处理后重建 DOM
  再插入"这条真实世界高频链完全没覆盖。实现走**污点传播 + 插入时复查**
  (不是"参数字符串含标记"),因此净化器摘掉 `onerror` 后天然不命中,
  且 `appendChild(createTextNode(...))` 这类实测不执行的对照形状不误报。
  `sink_matrix.py` 加 9 个契约形状,实测 must-confirm 21/21、no-exec 全静默。
- **jQuery sink 覆盖**(Phase 186):`.html` / `.append` / `.prepend` / `.after` /
  `.before` / `.replaceWith` 六个此前从未被测量过的方法接入;
  `benchmark/vendor/jquery.min.js`(3.7.1)vendored 进仓库,离线可跑。
  矩阵 must-confirm 27/27。
- **PortSwigger cheat sheet 技术面覆盖对照**(`benchmark/portswigger_corpus_coverage.py`):
  822 条向量按 cheat sheet 自身的分区分组,主指标只取 no_interaction 组
  (事件 23.1% / 标签 71.4% / 协议 100%)。三条局限写在脚本 docstring 里:
  字符串出现 ≠ 语义等价、覆盖 ≠ 能检出、忽略浏览器支持差异。
- **noqa 卫生门禁**(`tests/test_noqa_hygiene.py`):含 `F401` 的抑制必须带原因。
  `pyproject.toml` 早就这么声称,实测 47 条里 40 条是裸的 —— 约定只活在配置注释里。
- **CSP allowlist → 第三方 gadget 执行链**(Phase 187,吸收 nuclei csp-bypass
  模板族 / renniepak CSPBypass):`csp.SCRIPT_GADGETS` 表(35+ 条 Angular/Vue/
  JSONP gadget)从 Phase 20 起只作静态建议;现在 `register_gadget()` +
  `gadget_bypass_payloads()` + `gadget_chain_relevant()` 把链跑通 —— 严格
  script-src 且 allowlist 已知 gadget 主机(唯一脚本路由)时,双引擎在反射点
  直接注入 gadget 载荷:framework 型(Angular 模板表达式)经 `template_angular`
  静态 machinery 确认,JSONP 型(token 骑在 src 属性上、静态诚实沉默)由真
  Chromium 执行确认。本机靶场实测 JSONP gadget 全链 `browser-executed`
  (`tests/test_csp_gadget_chain.py`)。
- **竞品吸收第三轮(Phase 188,四项)**:① async JSONP gadget 对位补全 ——
  静态不确认但浏览器真实可用时发出 candidate(Phase-183 外层 wrapper 做
  headless 确认/否证),无浏览器保持沉默,与 sync 语义逐字一致;②
  kxss 式反射元字符 triage 落进 finding(`reflected_meta` 字段:哪些元字符
  被原样反射)与 HTML/JSON 报告;③ 盲打回调收集面 —— collector 载荷
  (cookie/localStorage/sessionStorage/referrer/URL/UA/DOM 片段,分段截断)
  + `SelfHostedListener` 记录 beacon query + `collect_oob` 落盘(ezXSS/
  XSSHunter 标配);④ `--wayback` CDX 输入源(gau/waymore 管道一键化:
  历史URL全部成为扫描目标,scope 分区与 --sitemap 同款)。
- **竞品吸收第四轮(Phase 189,四项)**:① **凭据 egress 守卫**(`core/egress.py`)
  —— 规则一条:凭据只跟着"操作者点名的源"走,顶层请求恒带,仅因响应
  `Location:` 才到达的源收不到同族 header;重定向仍跟随、body 仍解析,判定语义
  零变化(对标 Dalfox GHSA-mph2-gf5w-6f9f 的修复);② **CSP 交付家族粒度** ——
  `script-src-elem`/`script-src-attr` 按 CSP3 语义**替换** `script-src`,
  nonce 使 `unsafe-inline` 失效的规则改为逐家族判定,预算门控/gadget 相关性/
  verifier 内联门三处消费者统一走 `csp.inline_blocked(header, family)`;
  ③ **净化器语料现代化** —— DOMPurify 版本线从"停在 2020"扩成三段修复线
  (<2.0.8 / <3.1.3 / ≤3.4.15,编号取自厂商 advisory 列表实测),新增 2026 年
  全部利用面所指向的**配置项**检测(IN_PLACE / CUSTOM_ELEMENT_HANDLING /
  SAFE_FOR_TEMPLATES / setConfig() / USE_PROFILES / ADD_ATTR 里的 on* /
  ADD_URI_SAFE_ATTR / ALLOWED_URI_REGEXP / RETURN_TRUSTED_TYPE),同版本
  横幅与 npm 路径两种形态去重为一条;④ **source map 摄取**
  (`core/sourcemap.py`)—— `sourcesContent` 里的未压缩原始源码进既有 JS
  挖矿通道,可读回时另记 `source_map_exposed`(low);每脚本最多取一个 map,
  引用指向别的源即不取。
  测试:`tests/test_egress_guard.py` 15 例(双 origin 真回环,含"同族 header
  必须沉默"与"同族必须保留"两侧)、`tests/test_csp_families.py` 18 例、
  `tests/test_sanitizer_modern_corpus.py` 13 例(含加固页必须沉默的反向对照)、
  `tests/test_source_map_ingestion.py` 17 例(注入式 fetch + 一条真 HTTP 往返)。
- **`--stop-at-cross-origin` 授权边界(Phase 189 续,对标 Burp "不跟随越权重定向")**:
  同一条规则从"剥凭据"升级为"不投递载荷" —— 页面 `Location:` 指向未点名源时请求根本不发出,
  调用方拿到 3xx 本身,运行末尾列出被拒绝的跳转("0 findings" 不得暗中意味着"停在别人的源上没看")。
  实现走 requests 可覆写的 `Session.resolve_redirects`:`send` 以 `[resp for resp in gen]` 取
  最后一个 yield 作为响应,因此**不 yield 就等于停止跟随** —— 无需合成响应,也不碰私有 API。
  CLI 端到端实测对照:默认关时一次扫描把 40+ 个探针带到第三方 loopback 源(且落地请求确认无
  `X-Api-Key`),开启后落地源 0 命中;同域跳转照常跟随、照常带凭据。
  async 侧凭据剥离照旧生效,"停止跟随"仅 sync —— aiohttp 的跳转循环在
  `ClientSession._request` 内部,实测 `on_request_redirect` 改不了下一跳目标,故 CLI 显式警告
  而不是假装支持(`_warn_async_partial_flags`)。
- **`--mcp` MCP stdio server(Phase 192,dalfox v3 parity)**:JSON-RPC 2.0
  逐行 stdin/stdout,实现协议稳定核心(initialize 版本协商 / notifications
  静默 / tools/list / tools/call / ping),stdout 只走协议、诊断只走 stderr。
  单工具 `xssentinel_scan` 同步驱动与 REST API 同款扫描路径,finding 压缩
  交付(proof/PoC 摘除、长字段截断、上限 200 条);找零结果是成功、扫描
  失败才 isError。测试 11 例含真子进程 stdio e2e。
- **PortSwigger 事件处理器语料补齐(Phase 192)**:新语料家族
  `portswigger_events` 48 条(40 个缺失的 no-interaction 事件 + 6 个缺失
  标签作宿主 + other 组 6 事件),参照基准 no_interaction events
  **23.1%→100%**、tags 71.4%→100%。不动 `html_element` 主族(205 条步长
  采样点零位移),双引擎各取样 2 条只花剩余预算;家族大小入测试钉。
- **HPP 探针 + 交互事件可测量化(Phase 193)**:① 同参数投递两次的
  HPP 探针(dalfox `--hpp`;首现 benign 次现 payload,只查首现的过滤器被
  绕过),双引擎 WAF 门控 + 标准验证 machinery;② requires-interaction
  事件可测量化 —— `interaction_events` 语料 27 条 + DOM 引擎/
  verify_headless 在 token 承载元素上派发合成事件集,headless 确认与
  dom_dynamic 命中从此覆盖 onpointerdown/onclick/ondragstart 族
  (参照基准 requires_interaction events 15.4%→49.0%)。门禁抓到并修复:
  派发 JS 自身含 marker 被 eval 钩子记为命中(12 个 strict 切片 FP),
  按既有 harness 旗标契约隔离。
- **stored-XSS dialog 闭环 + session 失效策略(Phase 194)**:①
  stored-dom 增加 opt-in 的 dialog 通道(dalfox --sxss / nuclei
  waitdialog 语义)—— 纯 `<script>alert('token')</script>` 存储载荷执行
  时不经过任何被钩 sink,曾是盲区;dialog 消息含 token 即记执行证据,
  仅作 sink 命中为空时的 fallback,且只对"marker 在注入代码里"的调用方
  开放(URL 源探针的 alert 只是显示,不是 XSS)。② `--session-check
  REGEX` 把失效探测扩展到响应体(200 页"请先登录" defeating 状态码检
  查),`--on-session-loss {relogin,abort}` 让死会话可以诚实停扫而不是
  无限重登;abort 走既有 BudgetExhausted 优雅停机。
- **GraphQL introspection 输入面 + 交互事件长尾(Phase 195)**:①
  `--gql ENDPOINT` introspect GraphQL schema,String 型 mutation 参数 /
  input-object 字段 / query 参数 / 字段名按写入侧优先合并进挖矿词表,
  端点成为扫描目标(inQL 对位;库存清单最后一个命名输入面缺口);②
  DOM 引擎合成事件集 25→~60 型、interaction_events 语料 27→63 条,
  requires_interaction events **15.4%→73.1%**(剩余为设备传感器/导航
  生命周期等不可诚实派发项,记账不追)。
- **浏览器渲染输入发现 + HPP body 位(Phase 196)**:① `--discover`
  渲染目标一次收割 LIVE 输入面 —— SPA 表单字段名并入挖矿词表,页面
  自己 fetch 的同源 API 端点(严格同源过滤)作为附加目标扫描(库存
  清单最后一个命名缺口:"无基于浏览器渲染后的动态输入发现");② HPP
  扩展到 form 体(裸 urlencoded 字符串重复参数,dict 无法携带重复键),
  JSON 载体仍归 pre-encode 管线。后续修复:sync body 位 finding 的
  `param_in` 曾硬编码 query(PoC 重放错位),已修并加 async 专项回归锁。
- **双引擎行为对等门(Phase 198,OPTIMIZATION 2.1 落地)**:12 端点反射
  切片双引擎同预算对跑,比较 (type, severity, confidence) 多重集 ——
  验收按 2.1 硬要求双向通过(摘掉 async 的 content-type 降置信 / concat
  重试,门各自变红)。门当天抓到第一类新分歧:async L7 层 shim 的
  findings 视图缺主循环裁定,polyglot fallback 只在 async 误发 —— 已修
  (shim seed + param_confirmed 哨兵),并修复两引擎 polyglot finding
  缺 confidence 键的报告元数据缺陷。
- **async 测试密闭性守卫(Phase 200,OPTIMIZATION 3.8 结案)**:3.8 记录的
  ~55s/_probe_param"判定 CPU"被实测推翻 —— 真凶是 L7 层载荷探针经
  独立 sync Requester 泄漏真网络(桩 session 的测试里每次不可解析域名
  DNS 超时 7-11s)。`_get_sync_requester()` 现在要求活跃的真实 aiohttp
  传输(`scan()` 置旗),否则拒绝、层如实降级。14/12 预算
  _probe_param 62.7s→0.44s。
- **报告层性能基线(Phase 199,OPTIMIZATION 2.2)**:1000 条真实形状合成
  finding 八格式实测 —— html 0.053s,比 2s 验收线快 38 倍,报告层不是
  瓶颈,不做重写;基准脚本 `benchmark/report_load.py` 与结果入库可复跑。
- **MCP 侦察工具 + unsafe-hashes 评估关闭(Phase 202)**:`xssentinel_discover`
  (headless 渲染收割 SPA 输入面)与 `xssentinel_profile`(kxss 式单请求
  反射画像,raw=/stripped=/encoded= 元字符分类)加入 MCP 工具面,Agent 可
  按 discover → profile → scan 链式侦察;unsafe-hashes 的"利用"经评估确认
  无反射面可行路径(精确 hash 匹配 = preimage 不可行),检出即终点。
- **GraphQL mutation 注入目标(Phase 204,--gql 收尾)**:每个含 String
  参数的 mutation 生成一个 JSON-carrier 扫描目标(query 模板 + variables
  对象),既有逐叶探针把全量 payload 梯子注入每个 String/ID 参数;
  必需的非 String 参数给样本值使 mutation 真正执行,selection set 用
  恒合法的 `{ __typename }`。
- **测试套件自身的两条门禁 + loopback 靶场端口卫生(Phase 206)**:
  - `tests/test_loopback_gate_placement.py`(5 例)**禁止模块级 loopback 门禁**。
    `pytestmark = skipif(not SOCKETPAIR_OK, ...)` 活在 Module 节点上、**无法按用例
    豁免**:主机劣化时整文件连"一个网络请求都不发"的用例一起跳过(实测
    `test_verify_carriers_live.py` 21 skipped 全跳,其中 6 条正是守 paramless
    兜底的纯断言)。正确形状是把门下沉到真正依赖 loopback 的用例,本条把该形状
    固化(含反证:注入违规用例必须变红,否则门本身是空转的)。
  - `tests/test_fixture_port_hygiene.py`(4 例)**loopback 靶场必须绑
    `("127.0.0.1", 0)`**。起因是 `test_xs_leaks.py` 解除模块级门后立刻转红,
    而根因不在 XS-Leaks 判定:源站**确实**发了 `Cross-Origin-Opener-Policy`,
    客户端却没在跟它说话 —— `netstat` 显示一个 2 小时前泄漏的 python 仍占着
    9002,`http.server` 的 `allow_reuse_address = 1` 在 Windows 上让**第二次
    bind 直接成功**(没有 `OSError` 可捕),所以 `for port in range(9002, 9014)`
    的探测循环自以为拿到了端口,实际连的是别人的服务器。代价是**一绿一红同时
    产生**:同文件的 `test_surface_found_when_opt_in` 本来就期望 1 条 finding,
    对着错误服务器也是绿的。**10 个**靶场改为 ephemeral 绑定 —— OS 保证独占,
    "被占"这个状态根本不存在,不需要探测也不需要回退。规则不给
    "看起来安全"的固定端口开口子(18xxx 段也不行:碰撞概率低 ≠ 不碰撞,
    而失败同样静默);唯一例外是客户端 *connect* 到已知端口,那不是 bind。
  - 顺带收尾了上轮 WIP 遗留:20 个文件下沉门禁后未删的 `SOCKETPAIR_OK` 导入
    让 `ruff check` 报 11 条 F401,已清(现全库 `All checks passed`)。
- **修复建议语料补齐 + 报告类型表对齐(Phase 207)**:从"用户唯一直接消费的
  产品面"往回查,量出三个独立缺口。
  - **① 8 个真实发射的 finding type 掉进通用兜底建议**。判据是三方交叉:
    `report.py` 认不认(它有 SARIF rule id 就叫认)+ 代码真的会不会发
    (`core/*.py` 里的 `"type": "..."` 字典与 `type="..."` 关键字两种形态都算)。
    结果是 `cors_misconfig` / `xs_leak_surface` / `upload_xss` /
    `stored_upload` / `stored_dom` / `source_map_exposed` / `bav` / `scenario`
    —— 八个全部在跑真实扫描时见过(有的直接出现在 `benchmark/results/*.json` 里)。
    后果不严重也不无害:**报告对一个 CORS 头回显问题、一个源码泄漏问题,
    给的建议是"对输出做上下文编码"** —— 方向错了,而且没有任何测试会红。
  - **② 四个类型在 report 的类型表里缺席**。`stored_dom` 由
    `scanner_stored.py` 发射、带真浏览器证据(`headless.outcome="fired"`),
    Burp/Nuclei 导出却渲染成 fallback slug `"stored dom (XSS)"`,SARIF 更是
    塌成通用 `XSSENTINEL-XSS` —— 一个存储型、浏览器确认的 finding 在
    code-scanning 里的可区分度**与一个反射型完全相同**;`upload_xss` /
    `stored_upload` 有 interop 名但没有 SARIF rule id;`scenario`
    (`core/scenarios.py`,`--scenarios` DSL 确认的多步链)**三张表里全都没有**,
    导出成 `"scenario (XSS)"`。四个类型的三处表已全部补齐。
  - **③ 新门 `tests/test_fix_advice_coverage.py`(12 例)把三条不变量都钉住**,
    含两条反证:注入"删掉 `source_map_exposed` 语料"与"合成一张只在 interop
    表里出现的报告表",门必须各自变红;**另有真实注入验证** —— 把 `scenario`
    从三张表里移掉,`test_every_finding_construction_is_report_visible`
    立刻红并指名 `['scenario']`。门自带防空转断言(表提取必须解出 ≥25 键、
    交集非空、`Finding(...)` 构造点 ≥8),因为"提取器静默返回空集"
    正是它要防的那种静默失效。
  - **判据收窄是关键,而且分两层**:`"type": "..."` 也会出现在 JSON schema 里
    (`"type": "object"`),所以第一层"发射集"刻意取宽,只在**与 report 的
    两张面向浏览器的表求交**之后才判定 —— 于是 `dom_sink` / `inline_handler`
    这类会被扫描器折叠成 `type: "dom"` 的子结果名天然出局,**不需要豁免名单**。
    第二层单独用更严的判据(`Finding(...)` 调用的 `type=` 关键字)抓
    "**根本不在任何表里**"的类型 —— `scenario` 正是这种,求交式判据看不见它。
  - 头一版提取器只走字典字面量,`cors_misconfig` 直接隐身(两个引擎都是
    `Finding(type="cors_misconfig")` 关键字形态)。**门漏掉一个类型就报不出它**,
    这正是本文件存在的理由,已补上关键字形态并写了注释。
  - 语料 123 → **131** 条;`_meta.entry_count` 由测试锁死与实际条数一致。
- **192 例全矩阵复测(Phase 206,与 9-24 基线同口径 10/6/90)**:sync
  **TP113 / FP0 / TN79 / FN0 / ERR0,f1=1.000**(742s);async
  **TP108 / FP0 / TN74 / FN0 / ERR0,f1=1.000**(912s,182 例计分 —— 10 例
  manifest 声明 `engines:["sync"]` 的存储型/二阶链路记 SKIP,不记通过也不记漏报)。
  产物 `benchmark/results/p206_full_{sync,async}.json`。**一处如实记账**:async
  `pos-elem-04` 前两次 attempt 都是 **FN 且 `requests=0`**(第二次直接 180s 超时),
  第三次 TP(20.33s / 29 请求)—— 按 Phase 97 口径这是环境形 FN,runner 的替换
  完整留在 `fn_retry` 注记里可审计(`first` + 三次 `attempts`),不是"跑绿就算数"。
- **外部效度对照第一次量出来(Phase 196b)**:`benchmark/run_cross_tool.py` 让
  XSSentinel / dalfox / nuclei 在**同一批靶**上跑分。文档 1.0 长期写"第三方对照
  需换机器",本机复核推翻了它:GitHub API 与 raw 可达、Go 代理(goproxy.cn)能
  构建 `hahwul/dalfox` v2.13.0(落 `C:\GoWorkspace\bin`,适配器的 `_find_tool`
  本来就按 GOPATH 解析)、nuclei v3.9.0 与完整 `nuclei-templates/dast` 早在机上
  —— 不可达的只有 github.com 的 release 资产下载。**60 例确定性分层切片**
  (按 `(ground_truth, context)` 每族先各取一条,不靠随机种子):
  XSSentinel TP35/FP0/TN24/FN1 **f1=0.986**(346s);dalfox v2.13.0
  TP26/FP1/TN22/FN10/ERR1 **f1=0.825**(1173s,3.4× 慢);nuclei v3.9.0 dast
  TP26/FP0/TN23/FN10/ERR1 **f1=0.839**(49s,7× 快)。产物
  `benchmark/results/phase196_cross_tool.{json,md}` 带工具版本与逐例矩阵。
  我方唯一那条 FN(`pos-xs-01`)是**打分口径**不是判定错误:XS-Leaks 审计层按
  设计给 low/firm,而这里"检出"定义为 high/medium/critical 的 XSS 级 finding;
  该层两个第三方工具根本没有。

### Fixed

- **DOM 汇聚点面:先问浏览器,再决定跟不跟竞品清单**(Phase 197 测量,
  `dev/_p197_sinkoracle/probe_sink_oracle.py`)。dalfox v3.2.0 宣称新增
  `FileReader` / `setAttributeNS` / `parseHTMLUnsafe` / 拖放 / 剪贴板 / 间接
  `eval` 一批 sink;把每条形状在真 Chromium 里用可归因源(location.search /
  hash)实测后:
  `setAttributeNS(null,'onclick', 攻击者串)` **执行**(下次点击即触发)、
  `var f = eval; f(串)` 与 `window['eval'](串)` **执行**、`setTimeout(串)` /
  `new Function(串)()` **执行**;而 `document.parseHTMLUnsafe(攻击者串)` 后
  append 进文档 **不执行**,`dataTransfer` / `navigator.clipboard.readText()`
  的源不是扫描器可归因的位置。所以"竞品加了"里有一条是我们不该加的
  (加了就是给浏览器否认的东西背书的静态主张),而有一条我们真的看不见:
  DOM 通道只 hook 了 `setAttribute`,`setAttributeNS` 投递的 `on*` 处理器
  全程无痕迹。已补 hook 并配**双层测试**(`tests/test_phase197_dom_sinks.py`:
  纯断言 hook 在位且顺序不破坏既有 hook + 真浏览器端到端报命中),
  守卫另做**变异对照**:把 hook 摘掉重跑同一条活体路径,命中集合变为空 ——
  证明这条测试依赖改动本身,不是"修好之后当然过"。
- **基准靶场自己把用例打成 ERROR**(Phase 196b,`benchmark/server.py`):
  `neg-header-01` 的 mode 是 `header_only` —— 把 query 值原样写进**响应头**;
  而全角变形族 `transform.t_fullwidth` 把 0x21-0x7E 整段映射到 U+FF01..U+FF5E
  (整条载荷都越过 U+00FF)。HTTP 字段值按 RFC 7230 只能是 latin-1,stdlib 的
  `send_header` 用 strict 编码 → 处理器内 `UnicodeEncodeError` → **连接在没有响应
  的情况下关闭** → async 侧把 90s 预算全花在一条它根本没拿到答案的用例上,
  严格门因此报 ERROR1。错的是尺子不是扫描器:加 `_safe_header_value()`,
  ≤U+00FF 逐字节原样通过(既有 header 反射期望一个都没动),>U+00FF 转百分比
  转义。**守卫带变异对照**(`tests/test_benchmark_fixture_header.py` 5 例):
  把 helper 打回恒等函数后同一请求必须仍然炸连接 —— 只测"修好之后"的测试
  证明不了任何东西。修后双引擎 strict 切片 **FP0/FN0/ERROR0**
  (sync TP36/TN28,async TP36/TN27 + 1 例 sync-only SKIP),产物
  `benchmark/results/phase196d_quick_{sync,async}.json`。
  范围说明:覆盖靶场 `_respond` 这条汇聚路径(GET `header_only` 模式实测触发);
  POST 与自定义头走同一个 `_respond` 因此同样受保护,但未单独设例。
  range3/range4 靶场当前没有任何"把请求值写进响应头"的模式,该缺陷对它们是
  潜在而非现实,未预先加代码。
- **`<meta http-equiv="Content-Security-Policy">` 不在判定视野里,造成一类 FP**
  (Phase 196b):阻断问询、nonce 复用、gadget 相关性全都只读响应头,而 Chromium
  对 meta 策略与头策略一视同仁。**先实测再改**(五条形状 × 真浏览器,
  `dev/_p196_csp_delivery/probe_csp_delivery.py`):头 enforcing 与 meta enforcing
  都让 dialog 沉默;头/meta 两种 report-only 都不阻断 —— 所以漏看 meta 是**过报**
  而不是漏报。`csp.policies(headers, html)` 把两条通道收进一个结构并区分强制模式,
  `csp.blocks_family()` 读**全部** enforcing 策略(多条同时生效时任一条阻断即阻断,
  不是取第一条就完事);`verifier` 的 inline / attr / js-uri 三个门与 sandbox 的
  升级门同改(sandbox 那条原先把 report-only 也算成"有策略",于是拒绝对一个根本不
  生效的策略做升级 —— 反向的 FN)。报告侧:`scanner_layers` 的 L7 不再拿
  report-only 当"可绕过的 CSP"(没有生效的保护,谈不上绕过),同时第一次能看见
  meta-only 页面的弱策略。测试 `tests/test_phase196_csp_delivery.py` 17 例,
  含 4 例真 Chromium 对照,把判定钉在浏览器行为上而不是钉在这份文件自己的意见上。
  **双引擎同步闭合**:`_scan_csp_async` 加 `html` 形参、调用点
  (`async_scanner.py:503`)传页面 body,两条引擎走同一个 `csp.policies()` 解析;
  测试按 (header, meta) 六种组合逐对比较 finding 数与 `csp_header`,防止再退化成
  "async 只读头"——本仓为这类漂移付过 concat 重试、content-type 降置信、
  JSONP gadget 三次账。
- **被扫页面可以选择接收操作者凭据的源**(Phase 189,工具自身安全):实测
  (requests 2.32.5 / urllib3 2.6.3)跨 host 302 只剥 `Authorization` 与
  header 形 `Cookie`,且按 **host 字符串**判跨源(`localhost→127.0.0.1` 算跨,
  `h:8080→h:9090` 不算),自定义 `X-Api-Key` 与无 domain 的 `--cookie`
  原样送达;aiohttp 3.13.3 则 header 与 jar cookie 全送。现由
  `requester.GuardedSession.send`(逐跳 —— requests 在 `send` 里重入处理重定向)
  与 `async_scanner._session_kwargs`(`on_request_redirect` 剥 header +
  `CookieJar.filter_cookies` 门控 jar,因 aiohttp 在该 hook **之后**才套 jar)
  双侧收口。另:`llm_pool` 的 provider `Bearer` key 改为 `allow_redirects=False`
  (OpenAI 兼容端点不重定向,3xx 落进既有失败分类)。
- **CSP 只读 `script-src` 造成双向判定错误**(Phase 189):
  `script-src 'self'; script-src-attr 'unsafe-inline'` 被整体判为"内联全禁"
  → 反射 `onerror` 被否证(FN)且 payload 预算被 `is_strict_inline` 切到早停档;
  `script-src https://cdn.example.com`(无 `'unsafe-inline'`)里的反射
  `<script>` 判为可执行(FP)。`script-src 'nonce-x' 'unsafe-inline'` 的
  nonce 还会越界吃掉 `script-src-attr` 的 `unsafe-inline`。三处消费者统一到
  家族判定,`verifier` 事件处理器分支改走 `_csp_blocks_attr()`,原文兜底分支
  改为"两家族都封死才否证"。
- **postMessage 探针的同源伪影**(Phase 187,吸收 DOM Invader origin-spoof):
  DOM 引擎的合成消息原以 `origin = location.origin` 派发 —— 带 origin 校验的
  handler 照样触发 sink 被判为跨源可利用,而浏览器永远禁止跨源消息冒充本源。
  改为只派发攻击者可达源(`https://attacker.example` + 沙箱 iframe 的
  `null`),有效 origin 校验的页面测量为沉默;`window.onmessage` 赋值形态
  一并覆盖;命中的 detail 显式写明攻击者源语义。

- **满分的考试里藏着一个陈旧答案**(Phase 189,全量 sync 矩阵抓到):
  `neg-sanitizer-01` 从 TN 变 FP —— 该 safe twin 用"DOMPurify 3.0.6 = 当前版本
  + textContent 安全汇聚"来表达"干净",而 3.0.6 自 CVE-2024-47875(嵌套 mXSS,
  3.1.3 才修)起**确实是易受攻击版本**。判定为真、**靶场时基陈旧**,所以改的是
  靶场不是判定:版本改 3.4.16(`integrity` 保留,否则会触发 sri_bypass
  "跨源脚本无 SRI" high,把一个 FP 换成另一个 FP;该哈希属 3.0.6,已在 docstring
  标明是装饰值)。定点复测 pos/neg-sanitizer-01 = TP/TN。
  同批把 `tests/vuln_server.py` 里两处"用 3.0.0 代表现代版本"的 sanitizer
  fixture 一并升到 3.4.16。

- **`adoptNode` 静默漏报**:它把节点**迁出**原文档,调用一返回 `node.ownerDocument`
  就已变成主文档,污点若在调用之后判定恒为 False,整条 adoptNode 链不报。
  `importNode` 不移动源节点所以踩不到,**正是它掩盖了这个问题**。改为先判污点再调原生。
- **jQuery 两个 FP**:`.text()` 只写文本、`.val()` 只写表单值,HTML 不解析,
  而 `wrapJQ` 判的是"参数字符串含标记" → 一直命中。两者已从包装列表摘掉。
  (`.attr()` 保留:属性值可以是可执行载体,收紧会引入 FN。)
- **jQuery 一整批 FN(更严重)**:`wrapJQ()` 只在 init 与 `DOMContentLoaded`
  各调一次,页面里同步执行的脚本在那之前就用 `$.append()`,6 个形状里 5 个整批 MISS;
  `jQuery.html` 因为内部走 `innerHTML` setter 而命中,正好掩盖了这个问题。
  改为拦截 `window.jQuery` 赋值,一挂上就包装。
- **lint 基线清零**:313 条 ruff(E/F/W:未使用导入、未定义名、死变量等)清零,
  并固化为 CI fail-fast 步骤,防止回潮。
- **README 基线表过期**:async 行仍写"TP104 / FN6 / recall 0.9455"(
  177 Phase 之前的旧账),已更正为 asyncfix 的 TP108/FP0/TN74/FN0。

- **push 精度门禁看不见 43% 的检测面(Phase 190)**:`benchmark.runner --quick`
  的 `per_class=5` 在按上下文字母序轮转的过程中就撞到上限停下,于是每次 push 只测
  5 正 + 5 负、且永远是排在最前面的那几个上下文 —— `html_element` 一家占 48 正 +
  34 负(矩阵的 43%),在 push 门禁里被测量 **0 次**。切片改为"每个
  `(ground_truth, context)` 取一条" = 64 例,正/负两条臂各自覆盖全部 36 / 28 个
  上下文。同时新增 `--strict-gate`(FP0/FN0/ERROR0 才过),取代在 10 例规模上
  "容忍 1 个误报 + 2 个漏报仍绿灯"的 `FPR>20% / recall<50%` 旧阈值;ERROR 也判失败,
  因为"没测到"不能让门禁显得"测过了"。本机(劣化 loopback)实测双引擎零容错通过:
  sync TP36/FP0/TN28/FN0/ERR0 370.3s、async TP36/FP0/TN27/FN0/ERR0(1 SKIP)267.3s,
  产物 `benchmark/results/phase190_quick_{sync,async}.json`。
  CI 侧:push 门禁从"只跑 sync"改成**双引擎都跑且带 --strict-gate**(历史上每一次
  "async 漏了 sync 的修复"都发生在 push 看不见的位置),`benchmark-full` 补 async 臂,
  `nightly-gate` 与 `benchmark-full` 的安装口径对齐 requirements.txt(此前缺 `ast`,
  声称"与作者本机同一入口"的作业里 AST 通道测试其实一直在静默 self-skip)。
- **文档口径与代码脱节**:`ci.yml`、`CONTRIBUTING.md`、`docs/OPTIMIZATION.md` 三处
  把 `--quick` 写成"98 例"(实际长期是 10 例),`run_benchmark.py` 写"10 cases",
  `run_benchmark_batched.py` / `run_dalfox_only.py` 把矩阵写成"98 用例"(现为 192)。
  新增 `tests/test_quick_gate_slice.py`(6 例)把这件事变成门禁:切片必须覆盖每个
  (ground_truth, context) 对、必须确定性、且**文档里写的数字必须等于代码实际产生的
  数字**,陈旧说法以禁止字面量的方式列出。


- **`tests/test_async_hidden_param_mining.py` 自 Phase 189 起就是红的(2 例),且失败
  位置随测试顺序漂移**:该文件的 `_FakeAiohttp` 桩没有 `CookieJar`/`TraceConfig`,
  而 Phase 189 的 async 凭据守卫开始用这两个名字。单跑在 `_egress_cookie_jar_cls`
  的 `aiohttp.CookieJar` 就炸;和别的 async 测试同跑时因为 `_EGRESS_JAR` 已被真
  aiohttp 填过缓存,报错点后移到 `_session_kwargs` 的 `TraceConfig` —— 也就是说
  **结果是顺序决定的**,而这正是"定点批次没跑到这个文件"能把它带到今天的原因。
  补齐两个桩 + 在换 fake 时隔离/还原模块级缓存,并新增一例
  `test_fake_aiohttp_leaves_the_cached_egress_jar_alone` 锁住污染方向:fake 造的 jar
  类若泄漏给后面的 `test_egress_guard.py`(它验的正是**真** `CookieJar.filter_cookies`
  闸门),那套测试就会变成"通过但什么都没测"。
- **source-map 披露发现的 emit 形状(Phase 189 遗留,`test_evidence_coverage` 2 例红)**:
  两处 `Finding(url=..., method=..., **fields)` 让静态审计看不见证据层级
  (helper 其实已经声明了 `evidence_class`,但混在 `**` 里读不出来)。改为
  `sourcemap.disclosure()` 返回**完整** kwargs(含 url/method),两处站点退化为
  可识别的 `Finding(**fields)` 纯转发,并按守卫自己的规矩把这两个 pass-through
  站点登记进豁免名单(带原因)。**层级仍然只声明一处,判定语义零变化**;
  `test_source_map_ingestion.py` 17 例含真服务器端到端,全过。

### Security

- **对外暴露但没设密钥 = 静默**:`--host` 的 help 明写"use 0.0.0.0 to expose
  externally",而 `--api-key` 是可选项,`_check_api_key` 在未配置时直接放行。
  这样起出来的服务会替调用方抓取任意 URL(还带着操作者的 `-b`/`-H` 凭据)并把
  扫描结果回吐给任何能连上端口的人 —— 一个 SSRF 预言机加一个漏洞信息泄露点。
  现在这种组合启动时打一条明确告警(不拒绝:挂在反向代理后面做认证是合法部署)。
  Phase 70 的同源防御**不是**这里的访问控制层:它是浏览器形状的(页面伪造不了
  `Host`/`Origin`),脚本客户端自己挑一个 `Host` 就能过 —— `curl -H 'Host: localhost'`
  实测可通,所以这条结论是量出来的,不是推的。
- **`--host 0.0.0.0 --api-key X` 此前对每个合法远程客户端返回 403**:Phase 70 的
  `Host` 白名单无条件生效,而远程客户端的 `Host` 必然是它真正访问到的地址
  (实测 `Host: 192.168.1.5:8000` → `cross_origin_blocked`),宣传的对外部署模式
  因此根本不可用。改为:**配置了 API key 时 `Host` 白名单让位于密钥**(密钥才是
  那道门),未配置 key 时白名单照旧全量生效;`Origin` 那一半(跨站状态变更)保持
  无条件。四条新测试锁住这个边界,含两条反向对照:无 key 同样请求仍 403、
  有 key 但带外来 `Origin` 的 POST 仍 403、有 key 不带 key 头的请求 401。
- **Flask 前端此前一道同源门都不执行**(Phase 196b,dalfox #1356 同一条修复的
  我方版本):Phase 70 的防 DNS 重组 / 跨站状态变更门写在 `StdlibServer` 里,
  而 `--use-flask`(以及"挂进现有服务"这条文档化用法)走 `FlaskServer`,在未配置
  `--api-key` 时(190 起会告警但仍允许的默认形态)重组页面可以直接 GET 读走扫描
  结果、跨站表单 POST 可以起扫描。测试套件里没有一条走 Flask 路径,于是这个不对称
  活了八个 phase。门抽成共享纯函数 `same_origin_ok()` 由两条前端各自调用(改一次门
  = 改所有对外形态),并补 `Sec-Fetch-Site: cross-site` 拒绝 —— 重组攻击下 `Host`
  与 `Origin` 都"看起来同源",只有浏览器说的这句不是。OPTIONS 预检走例外:它是
  协商不是状态变更,stdlib 的 `do_OPTIONS` 从不经过这道门,拦下来只会让
  `--cors-origins` 明确放行的源连真实请求都到不了(这条功能回归是我落地后实测
  才发现的,已修并补测试)。测试 12 例:共享函数五态 + 两条前端**逐用例同构**断言 +
  反向对照(本地客户端与不带浏览器头的 curl/SDK 不受影响)。MCP 走 stdio,不适用。


### Changed

- **async 引擎 Mixin 化(Phase 191,纯移动)**:`async_scanner.py` 3124 行 →
  **1534 行核心** + `async_scanner_layers.py` 991(预编码/DOM/高级层/请求层/CSP/
  CORS/XS-Leaks/上传/JSONP/盲打)+ `async_scanner_crawl.py` 321(隐藏参数挖掘 +
  端点/source map 挖掘 + BFS)+ `async_scanner_common.py` 270(共享 helper)+
  `async_scanner_verify.py` 136(Phase 183 的 headless 确认外层)。它当时是全库最大
  文件、已是当年拆掉的 `scanner.py` 核心的 2.5 倍,违反本项目第一条约定;而
  "async 漏了 sync 的修复"已经付过两次账(concat 重试、content-type 降置信)。
  **"纯移动"是被量出来的,不是被声称的**:`dev/_p191_baseline.py` 把 42 个方法的
  `inspect.getsource` 逐个哈希存档、搬完再比 —— 25 个换了归属文件、源码逐字节相同、
  无方法丢失;被裁掉的模块级名字逐个验证"全仓零外部引用"才允许消失。
  `_EGRESS_JAR` **刻意不再导出**:`from x import name` 拷的是值,一旦做别名,
  "重置缓存"的测试就会写在别名上而真实缓存照旧 —— 一个不再守卫任何东西的守卫。
  行为侧:64 例 async 切片**逐用例** verdict + findings_count 与拆分前全等,
  **请求数 7415 → 7415**(发包行为都没变),产物
  `benchmark/results/phase191_async_after_split.json`。
- **三个"按文件路径锁定调用点"的守卫改为遍历 async 引擎全部模块**:`test_async_wiring`
  (此前只读 `async_scanner.py` 一个文件)、`test_layer_accounting` 的 SITES 路径、
  `test_evidence_coverage` 的 committed 名单。这三个守卫拆完都**响亮地红了**而不是静默
  放行 —— 正是它们该有的行为;每个还补了一条前提断言(文件数 == 5、每个文件非空、
  必须找到调用点),防止"扫描集合空了"退化成空转。同轮把
  `test_the_guard_sees_the_real_lazy_call_sites_not_just_the_synthetic` 的变异目标
  改为按 (模块, 行) 定位,并修掉 `[^#]*` 跨行正则造成的 5 个假"悬空引用"。
- 40 处裸 `noqa: F401` 补上原因(Mixin 运行时引用 / 可选依赖探测 / re-export
  三类);4 处 `noqa: BLE001` 摘除 —— `select = ["E","F","W"]` 下 BLE 永不触发,
  那些是死注释(其中"reaper never dies"这类设计说明作为普通注释保留)。
- `docs/OPTIMIZATION.md` 修订:现状数字按当前工作树重取(三个大文件原偏差
  100~220 行)、1.1(ruff CI 门禁)标记为已完成、新增 1.0 外部效度章节。

- **对照尺子的四处失真,每一处都先让尺子自证(Phase 196b)**:
  ① 适配器用 `--max-payloads 10 --max-transforms 6` 而门禁跑 14/12 —— 对照里测的
  是比发布口径更弱的自己;预算改为 `benchmark/runner.py` 单一定义
  (`DEFAULT_MAX_PAYLOADS` / `DEFAULT_MAX_TRANSFORMS`),适配器 import 而不是再抄。
  ② 适配器把所有目标拼成 `<path>?q=test`,丢掉了 cookie-tossing 用例需要的
  `sub.localhost` host 别名与 6 条用例的 per-case 旗标(`--oob self` /
  `--audit-xs-leaks`);改为共用 `runner._build_target_url` + `_case_extra_args`。
  **这一改直接改写了结论**:首跑我方 3 个 FN 里有两个(`pos-ctoss-01`、`pos-tb-01`)
  是尺子造成的,修完变 TP —— 差一点就被当成"检测面漏了"去改判定。
  ③ 子进程输出按 locale(本机 GBK)解码,第三方工具吐一个非 GBK 字节就在
  `subprocess.run` 里抛异常;旧错误记账只认两种形状,其余被当成"未检出"计分。
  现在显式 UTF-8 + `errors="replace"`,且**任何** error 一律记 ERR("没测到"),
  不再伪装成 TN/FN。④ 默认端口 8896 落在 Windows 动态保留段的惯用区间(179 的
  教训)→ 迁 18896;新增 `--sample N` 确定性分层切片、被比工具版本戳,以及
  `engine_fingerprint_start/end` —— 我方每条用例都是新起子进程重新 import 引擎,
  树在动的时候逐例数字没法归因,本轮两次作废的 run 就是靠它确认的。
- **依赖双源治理(`requirements.txt`,2026-10-01)**:改为 `-e .[dev,async,ast,api]`
  单行委托,版本约束只留 `pyproject.toml` 一处。此前它把 aiohttp / playwright /
  flask / esprima / pytest* 全部平铺成必装,与 pyproject 的 core + extras 分组
  **语义不一致** —— 两条安装路径装出来的环境不是同一种(按 requirements.txt 装
  会连 dev 测试依赖一起装上)。比文档原建议的 `-e .[dev]` 多带三个 extra,是为了
  与旧文件的**实际安装结果等价**,避免治理顺手把别人的环境降级;刻意不含
  `headless`,因为 playwright 还需 `playwright install chromium`,CI 与 README 都
  把它当独立可选步。已用 `pip install -r requirements.txt --dry-run` 验证可解析
  (`Would install xssentinel-1.0.0`),四个 extra 名与 pyproject 逐字核对无缺失。
- **死代码清理(2026-10-01)**:删 `tests/test_param_miner.py::_crawl_self`
  (重构残留 —— 同一个类里两个真实测试各自内联构造 fake,全库零调用方;删后该
  文件 21 例全过);`tests/_test_coverage_demo.py` → `dev/coverage_demo.py`,并把
  它自带的端口 **8898 → 18456**(8898 正落在 Windows 保留段 8810-9109 内,与上条
  端口迁移是同一个坑);`dev/verify_*_20260902.py` 三个一次性验证脚本归档进
  `dev/attic/`。
- **sandbox.py 第一刀拆分(纯移动,docs 1.3)**:2395 行 → `sandbox_common.py`
  (136 行,两边共用的 Node / Doc / VOID / serialize_text 等 7 个名)+
  `sandbox_parser.py`(1125 行,`_Parser` 与其 32 个专属表)+ `sandbox.py`
  (1320 行,判定半边与 CLI)。依赖严格单向 `common ← parser ← sandbox`,无循环。
  选**兄弟模块**而非 `sandbox/` 包(沿用 `scanner.py` + `scanner_crawl.py` 的既有
  惯例),是为了**外部 import 路径一行不改**,包括 `benchmark/probe_svg_case.py`
  直接引用的私有名 `_SVG_ATTR_CASE` / `_MATHML_ATTR_CASE`,以及 `probe_breakout.py`
  读的 `sandbox.FOREIGN_BREAK`。
  搬运过程中识别并修掉三个"搬家伤":① 定义上方的 `#:` 来源注释会随行区间被丢掉
  (第一版丢了 362 行,而那正是写着"MEASURED, not recalled from the spec"和数据出处
  benchmark 的部分);② 文件尾的 `if __name__ == "__main__":` 不属于任何
  def/Assign,第一版直接删掉了 `python -m xssentinel.core.sandbox` 这个 CLI,
  **而没有任何测试发现**;③ 分区顺序必须**先取 common 闭包再划 parser**,反过来会让
  `serialize_text → NO_ESCAPE_TEXT` 变成 common 对 parser 的反向依赖,直到运行时
  才炸 `NameError`。验收:`ruff check .` 全绿、引用 sandbox 的 12 个测试文件
  **174 例全过**(与拆分前基线逐条一致)、CLI 实跑通过(`state=LIVE`)。

## [1.0.0] - 2026-09-29

首个正式版本。以"检测维度最全、架构最干净、最易扩展"为定位的多层级 XSS
检测框架。

### Added

- **双流水线引擎**:sync(线程池)与 async(aiohttp)两条扫描管线,192 例
  精度矩阵双引擎对齐(async f1=1.000,TP108/FP0/FN0);`--headless` 真无头
  确认双引擎同等可用(async 走专用线程池 + 重放三元组去重,range4 实测
  browser-confirmed 23/23)。
- **九层检测体系**:反射探测、WAF 自适应绕过(23+ 变形家族 REGISTRY)、
  DOM 静态污点 + JS AST 数据流、存储型(注入→展示页)、盲打 OOB
  (自托管监听器 / interactsh)、无头浏览器真实执行确认、模板 SSTI、
  框架 DOM sink(React/Vue/Svelte/Lit/Angular)、传输层(CORS / XS-Leaks /
  header / path / cookie / error-page)。
- **上下文感知注入**:20+ 种反射上下文分类,多反射点按执行优先级选主上下文。
- **场景 DSL**:Nuclei 风格声明式多步检测流;CSP nonce 泄露自动利用链。
- **输入面导入**:批量文件/stdin、HAR、OpenAPI/Swagger、Burp/ZAP 原始请求、
  被动代理(--passive,含可选 MITM HTTPS 拦截)。
- **六格式报告**:HTML / JSON / CSV / SARIF 2.1.0 / JUnit / Markdown,外加
  Burp XML 与 nuclei YAML 模板导出(按 finding 真实载体重放)。
- **HTML 报告统一设计系统**(`core/report_theme.py`):明暗双主题、严重度
  筛选/搜索/排序、payload 一键复制、可复现 PoC 目录、截图证据、覆盖率与
  合规映射章节;零外部依赖,离线可开。
- **verify-fix 复测 / diff 基线对比**:CI 友好的 PASS/FAIL 门禁语义。
- **benchmark 套件**:98 / 192 例精度矩阵、分批抗劣化跑法、range3(SQLite
  应用靶场)与 range4(React/Vue 真实框架 SPA 靶场)双引擎评分。
- **API 服务**(`--serve`,flask extra):任务化扫描、指标、通知;LLM 池
  (`--ai-report`)可选增强。
- MIT LICENSE、CONTRIBUTING.md、SECURITY.md。

### Fixed

- 版本号单一源(pyproject dynamic version;SARIF driver 版本不再硬编码)。
- fresh-clone 可复现:`report_theme.py`、`mxss_verify.py` 入库,本地
  git 排除项升入共享 .gitignore。
- CI benchmark-full / nightly-gate 补 `async` extra;esprima 版本下界对齐。
- HTML 报告自身不成为 XSS 载体:载荷全转义、仅 http(s) URL 可点击、
  客户端 JS 零数据插值(测试锁定)。
- markdown 报告的 GFM 表格注入与围栏击穿;UTF-7 语料条目编码错误;
  header 载荷交付 PoC 编码错位;XHR 去重泄漏(详见 AGENTS.md 178b)。

### Security

- LLM provider 密钥移出版本控制,仅保留脱敏模板。
- 全仓库密钥模式扫描通过(仅合成测试键)。
