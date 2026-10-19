# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式;
版本号遵循语义化版本。详细的迭代决策记录见 [AGENTS.md](AGENTS.md)。

## [Unreleased]

### Verified

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

- **同一靶场的召回账:9 条 XSS 挑战,当前扫描模型能确认 4 条(Phase 270/275/276)**:
  上游 `data/static/challenges.yml` 共 **9 条 XSS**,逐条对照(不把"没测"算成"没漏"):

  | # | 挑战 | 面 | 状态 |
  |---|---|---|---|
  | 1 | DOM XSS | `#/search?q=` | **已确认**(browser-executed) |
  | 2 | Reflected XSS | `#/track-result?id=` | **已确认**(browser-executed) |
  | 3 | Bonus Payload | 同 #1 的输入框,换载荷 | sink 已覆盖;该载荷变体未单独测 |
  | 4 | Video XSS | 促销视频 URL | 未测(需要另一条上传面先行) |
  | 5 | API-only XSS | 直接打 API 实体 | **当前模型够不着**:需管理员会话 + 写 |
  | 6 | Client-side XSS Protection | 注册用户 → 后台用户列表 | **已确认(Phase 276)**:`POST /api/Users` 的 email 原样落库;管理员页真实弹窗(手工 `<iframe src=javascript:alert(2)>@juice-sh.op`),扫描器的 `<<script>` 载荷只到 sink 不执行 |
  | 7 | Server-side XSS Protection | Customer Feedback 评论 | **已确认(Phase 275)**:`stored_dom` high/high,登录后 `/#/administration` 的 `Element.innerHTML`,Chromium dialog 实弹两次 |
  | 8 | CSP Bypass | 自家 RegEx 过滤的旧页面 | **够不着**:需登录 + CSP 注入载荷 |
  | 9 | HTTP-Header XSS | `X-Forwarded-For` → 最后登录 IP | **够不着**:需登录 + 自定义头 |

  准确读法:矩阵证明的是**精度与交付链路**(0 条非预期 finding),召回是 **4/9**,
  不是 5/5。剩余 5 条里 3 条(5/8/9)被"认证 + 写 + 二次查看"挡住,1 条(4)依赖另一条
  上传链,1 条(3)是同 sink 的载荷变体 —— 都不是检测层漏报。

### Added

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

- **四个靶场 runner 都没有"楔死重试",本机一进楔死窗口就整面变红(Phase 269)**:
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

- **`docs/OPTIMIZATION.md` 1.5 的三类病因已各自改掉,但两条一般规则没立**(Phase 210b):
  ① 静态层一律 `proof=None` —— "不可核对的高危"应当被门拒绝,这需要跨**全部**静态层的
  证据形状门;② "无浏览器证据 + 无 proof ⇒ 至多 medium" 的**通用**降档规则,需要自己的
  对照矩阵与全量矩阵复测。本轮按每种错各自的证据改了各自那一处,没有合并成一条通用规则。

- **DOM finding 不带参数名(本轮量到,未修)**:真实靶上 browser-executed 的
  `dom_dynamic` 是 `param=None`,报告参数列因此为空,`verify_fix` 的重放只能走
  `params["_"]` 兜底载体,修的人看不出该改哪个键。
  **注意这不是"缺一条 curl"**:fragment 投递服务端永远收不到,`curl` 反而是误导,
  PoC 里自动导航的 HTML 才是正确且可执行的重放(它已在)。缺的是**键名**。

- async 爬到的**非** fragment 端点仍只跑反射层(sync 对每个爬到端点跑全套页面层);
  见 `docs/OPTIMIZATION.md` 2.1.1。
- 真实靶场上浏览器爬取宽度不稳定(实测同命令 18 / 22 / 70 / 70 / 70 / 74 端点),
  以及 WAF 误检(Juice Shop 被判 `Generic/Unknown WAF` / `Cisco ACE`)未动 ——
  后者属判定面,需单独测量。

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
