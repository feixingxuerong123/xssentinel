# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式;
版本号遵循语义化版本。详细的迭代决策记录见 [AGENTS.md](AGENTS.md)。

## [Unreleased]

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

### Fixed

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
