<!-- agenthub:generated source=.agenthub/PROJECT.md at=2026-08-30T13:12:04.248 hash=ede70d8e1bf1 -->
# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

## 规则约定

- scanner.py 已 Mixin 拆分(1101 行核心 + 三 Mixin + findings):新增能力进对应 Mixin,不堆回主文件
- async_scanner.py 已同样 Mixin 化(1534 行核心 + layers/crawl/verify 三 Mixin + common,Phase 191):新增 async 能力进对应 Mixin,不堆回主文件;搬代码与改逻辑绝不混在同一轮
- fix_advice.py 数据化(141 行引擎 + JSON 语料):改建议优先改语料
- 多步检测优先写场景 DSL,而非过程式代码

## 任务与进度

- [x] 覆盖率攻坚至 925(report 六格式 + async 深层路径)
- [x] P0 工程质量三件套 + P1 梯队(Playwright 浏览器复用、payload 语料补强)
- [x] **当前迭代目标:让判定有测量支撑,而不是让基准更好看(Phase 176f–176r; 176f–192 全程在此主线上,187 origin 测量 / 187+192 CSP gadget 链 / 188 盲打
  收集面 / 190 门禁量尺 / 192 MCP+语料 100% 均为测量化落地)**
  - [x] 176f 补齐最后一个未覆盖层 → 50/50:`*.localhost` 解析到 loopback,
        可造出真实父子域对(L8_cookie_tossing),无需 DNS
  - [x] 176g 独立靶场红队验证(召回 9/9、诱饵 5/5 沉默);顺带补上从未被
        任何用例执行过的 content-type 分支(**层覆盖 ≠ 分支覆盖**)
  - [x] 176h 把独立靶场固化成常驻回归 `tests/test_redteam_independent.py`,
        每轮门禁都跑,不再依赖"手气好的时候手动跑一次"
  - [x] 176i 用 Chromium 全量 oracle(60×20=1200 cases)给纯 Python 沙箱重新打分,
        修掉 MISSED/OVER —— 结果 `tests/test_sandbox_fidelity.py` **8/8 passed,
        MISSED 0 / OVER 0**。唯一分歧(mxss-body-br × iframe_src)经**对照重跑**
        证明是 iframe settle 等待不足(300ms→1500ms),**沙箱一直是对的**
  - [x] 176j oracle 重采:矩阵 60×20=1200 → **84×20=1680**,补进 corpus_gap 指出的
        24 个语料家族各一条代表载荷(只把 alert(1) 换成 sentinel),
        产物 `benchmark/results/browser_dom_oracle.json`
  - [x] 176j 续:1680-case oracle 已重新给沙箱评分 —— `tests/test_sandbox_fidelity.py`
        **8/8 passed**;parser 臂 scored 1676 / **MISSED 0 / OVER 0** / UNKNOWN 60(3.6%),
        innerHTML 臂 scored 1680 / **MISSED 0 / OVER 0** / UNKNOWN 60。
        即 176j 新纳入的 24 个 corpus_gap 家族**没有暴露任何沙箱误判**。
        注:评分器是**纯 Python 重放**,不启动浏览器,2 秒跑完 1680 行 ——
        oracle 一更新就该跑,没有"太贵"这个借口
  - [x] 待定(需人决策)→ 179 已拍板:JSON 反射 severity 连 confidence 一起降
        (severity-only 消费者不再误判;红队契约同步更新)
- [x] **176u 分层记账诚实化(接手未提交 WIP 并修完)**:touch 移到层真实调用之后,
      失败路径落 `status="failed"` 行;测试的 AST 匹配器补上"作为 callable 传给
      `asyncio.to_thread` 的层函数"形态(否则对 async 恒空转)。3/3 passed
- [x] **177 多反射点上下文选择**:两个引擎原来都只按 marker 的第一处反射分类
      (`rank_contexts` 从出生就是零调用),marker 先落惰性上下文(注释/导航高亮)
      后落可执行上下文时,可执行语料永远不会被发。`context.analyze_all()` 按执行
      优先级选主上下文(单反射行为逐字节不变),次上下文候选排队尾不增预算。
      `tests/test_multi_reflection_context.py` 6 例;sync 192 例 f1=1.000 零退化
- [x] **177 续:async 首次与 sync 全量对齐**。FN 漂移分解:so2/scn×4 是 176s 的
      engines 门补上前的旧账(现已 SKIP);其余为环境伪影(隔离复跑全 TP);
      唯一稳定真分歧 neg-filter-05 = async 主循环缺 Phase 166 concat 重试
      (它只存在于需要 WAF 指纹的位置变换分支,无 WAF 的关键字过滤器永远够不着)。
      已补进主循环(escaped 跳过,不破 27-1 收敛预算)。
      **async 192 例 TP108/FP0/TN74/FN0,f1=1.000**(`benchmark_20260925_asyncfix.json`),
      此前最好 0.9455;红队 15/15(阳性现在断言 type/severity/confidence)
- [x] **178b 测试优化六批 + Range3 第三方意见靶场**:敌意输入套件打进交付层与判定层
      (report 8%→83%、param_miner 12%→81%、spa_crawler 8%→45%、poc 9%→73%、
      transform 0→95%),抓到并修复 6 个真缺陷:markdown 单元格注入 + 围栏击穿、
      header 载荷交付 PoC 编码错位、XHR 去重泄漏、**UTF-7 表 4/9 条目编码错误**、
      L8 spy 测试契约过时;async 错误分类学(预算/熔断传播 vs 传输错误降级)首次成测试。
- [x] **178c Range3(range3/)**:SQLite 持久化 + 登录会话 + 混合内容类型的"应用"靶场,
      ground truth 从服务器行为独立撰写,runner 双引擎评分。首轮 sync TP6/FN9 →
      暴露并修复 6 个扫描器缺陷(cookie 单形状、解码回显容器到不了预编码、
      容器检测结构字符过严、JWT 盲注漏已渲染字段、**async 缺 content-type 降置信
      (真 FP)**、async pre-encode payload_survived 错杀 JWT)。终局双引擎零 FP 零 FN
      (sync 16TP, async 14TP + 2 SKIP sync-only)。runner 四条教训固化注释:
      参数须写入起始 URL、连字符路由、stored 标志要全 URL、CLI 解析 -u query
      不做百分号解码。
- [x] **179 决策两项 + 环境两谜案**:JSON 反射 severity 连 confidence 一起降
      (severity-only 消费者不再误判;红队契约更新);变形上下文门控经沙箱
      23×4 实测后**决定不门控**,矩阵落盘 transform.py 设计文档。环境侧查明
      **Windows 保留端口段 8810-9109 吞掉全部惯用端口**(netsh excludedportrange),
      全项目默认端口迁 18xxx 段;三 fixture 服务器启用 HTTP/1.1 keep-alive
      (HTTP/1.0 每请求一条连接 → TIME_WAIT 风暴 → 临时端口耗尽)。遗留:
      test_benchmark 进程内 connect 挂起超 settimeout,见
      dev/WEDGE_test_benchmark_20260927.md。

- [x] **180 Range4 真实框架 SPA 靶场(range4/)**: React 18 `dangerouslySetInnerHTML`
      / Vue 3 `v-html` 对上自动转义的文本节点双胞胎, vendor bundle 是 vendored 进仓库
      的上游发布版。**构造效度先做**: `dev/_r4_construct_probe.py` 在无浏览器前提下证明
      `-safe` 双胞胎的服务端 HTML **不含** attacker 字符串 —— 首版靶场就栽在这里:对照页
      也把参数反射进服务端 JS config line,而那本身是 script-string sink,于是四例全
      confirmed、"safe" 被量成 FP,**错的是靶场不是扫描器**。
      终局**双引擎 8/8 对**(sync / async 各 TP2 FP0 TN2 FN0);runner 现在落盘
      `range4/results.json` 且带门禁语义(FN/FP/ERROR ⇒ exit 1),已挂进 CI 的 tests job。
      顺带挖出的**新缺口**:**async 模式静默忽略 `--headless`** —— AsyncScanner 根本没有
      verify_headless 接线(sync 在 `Scanner._record` 里逐 finding 确认),于是 async 的
      反射型 finding 全是 high/high 却**没有浏览器证据**:本轮 sync 12/12 confirmed,
      async 仅 1/23(且那 1 条是 DOM 层硬编码的 `confirmed=True`)。已先做诚实化:
      `--headless` 进 sync-only 警告列表(两条 async 路径都加)。
- [x] **184 同类对比吸收(DalFox / Arjun / ZAP 调研 → 两项落地)**:全盘对比
      2025-26 活跃同类(DalFox 的 skip-param/sitemap/pipe、Arjun 的响应稳定性
      与无反射参数发现、ZAP 的规则级策略)后,按"真实差距 × 架构契合 × 可
      离线测试 × 不动判定语义"落地两项:① `--sitemap URL_OR_FILE` 输入面
      (core/sitemap_import.py:sitemap index 递归抓子图(上限 20)、urlset、
      纯文本 sitemap.txt(非 URL 行过滤,HTML 错误页不会变成垃圾目标),
      `<loc>` 越域 URL 复用 HAR 同款 scope 分区(--allow-host/any 语义一致),
      单文件 8MB 上限);② `--skip-param A,B,C`(双引擎 L1 探针循环跳过 +
      scanner_crawl 单钩子同时覆盖双引擎挖矿;内置 38 条追踪噪声表
      (utm_*/gclid/fbclid/…)只在挖矿候选过滤生效——页面已声明参数仍被
      主探针覆盖,**结构上不可能造成 FN**)。Arjun 式无反射参数线索核查:
      mine_params 本就带 length_delta 差分且调用方有 fuzzer 差分 triage,
      不重建。测试:tests/test_sitemap_input.py(fetch 注入为主 + 一条真
      HTTP 回环路径,死子图容错)+ tests/test_skip_params.py(双引擎探针
      过滤/挖矿过滤/CLI 解析)共 11 例;回归批 68 例全过;benchmark quick
      FP0/FN0;新文件 ruff 零债务。README 徽章 + 输入族用法文档同步。
- [x] **183 async --headless 接线(待决策项落地方案 B,用户拍板)**:`AsyncScanner.scan`
      重命名为 `_scan_raw`,新外层 `scan()` 拦截全部 finding 走真无头确认——
      专用 `ThreadPoolExecutor(max_workers=headless_concurrency)` 经
      `run_in_executor` 调 `verifier.verify_headless`(Playwright sync API 线程绑定:
      **executor 宽度 = 浏览器实例上限**,cap=1 全程共用一个 Chromium;worker 线程
      无运行中事件循环,恰好满足 get_shared_browser 的启动前提)。去重键 = 精确重放
      三元组 (url, param, payload);token 从 payload 的 alert 参数现场提取
      (mark() 的语义 = 对话框消息即 token,三形态正则 + marker 兜底,**提取失败诚实
      跳过**——不可归因的重放只该保持未验证,不该冒 browser-refuted 的险)。跳过规则
      与 sync 对齐:OOB 已确认 / 已带浏览器证据 / 占位审计载荷 / JSON 载体(param_in
      =body 且 json_body 非空);评级复用同一 `_grade_evidence`,双引擎证据词表一致;
      验证异常降级为 errored 不杀扫描。CLI 两条 async 路径的 sync-only 警告收敛为
      `_ASYNC_SYNC_ONLY_FLAGS`,`--headless` 毕业。**实测 range4 双引擎**:async
      browser-confirmed 从 180 时的 1/23 → **23/23 与 23/23**(两阳性用例),
      门禁 TP2/FP0/TN2/FN0 双引擎对齐 exit 0。新测试
      `tests/test_async_headless_verify.py` 19 例(无浏览器无网络,fake _scan_raw +
      录制型 fake verifier);存量 async 套件 88 例零回归。
      续:首推 CI 唯一红点是 `test_stealth` 的墙钟 flake(断言两次 acquire 间
      开销 <1us,CI 负载下量到 1.1us;2345 passed / 1 failed,与本改动无关)
      —— 两处计时断言改为行为等价 + 10ms/1ms 容差(契约不变:足额 pacing、
      不超间隔、非半程),2345 例中的其余全部绿。
      **再续:CLI e2e 矩阵(dev/_cli_probe/cli_matrix.py,16 项全过)抓到一个
      真缺陷并修复**:CLI 端 `--poc-dir` 自 Phase 139 起产出永远只有 INDEX.md
      ——`write_poc_dir` 只解包 dict 形态 finding(`isinstance(f, dict)`),
      而 CLI 传的是 Finding 对象 → 全部落空 `{}` → 每个真实扫描的 12 个
      finding 全被当"无 PoC"跳过(dict 入参的单测看不见这条路径)。修复改用
      全库通行访问器 `f.data if hasattr(f, "data") else f`,新增双形态回归测试
      (test_report.py);矩阵实测 INDEX 正确列出 reflected-10.html/.sh 等工件。
- [x] **181 前端 UI 统一重做(report_theme.py)**:四个 HTML 交付物(主报告 /
      verify-fix / diff / benchmark)原本各持一份手写 CSS 拷贝,现统一接入
      `xssentinel/core/report_theme.py` 单一设计系统:明暗双主题(令牌化,
      `<head>` 内联 boot 脚本防闪白,无 JS 时回退 `prefers-color-scheme`)、
      零外部依赖(离线/file:// 可开)。主报告新增:严重度筹码 + 类型下拉 +
      文本搜索三重筛选、全列点击排序(severity/confidence/headless 按
      data-val 权重)、payload/curl 一键复制、严重度分布条、SCAN INCOMPLETE /
      BOUNDED READ 升级为独立告警条、表格容器内吸顶表头、响应式 + 打印样式
      (打印自动展开全部 `<details>`)。**JS 全静态零数据插值**,报告自身的
      XSS 契约(`href="javascript:` 禁现、载荷转义)原样保住;coverage.py 的
      两处亮色硬编码内联样式改 `.cov-warn` 主题类(暗色下不再消失)。
      报告相关 9 个测试文件 270 例全过(唯一断言更新:
      test_ai_report 的 `<h1>XSSentinel` 字面量 → 匹配带品牌 SVG 的新 h1);
      明暗双主题截图与筛选/排序/复制/切主题交互经 Playwright 实测,
      样张在 `dev/_ui_probe/`。

- [x] **182 交付就绪化(delivery-readiness pass)**:全维度评估后修掉的交付阻断项
      与质量问题 —— ① **LICENSE(MIT)落地** + pyproject `license` 字段(此前
      无许可证 = 法务硬阻断);② **版本单一源**:pyproject 改 `dynamic =
      ["version"]` 从 `xssentinel.__version__` 解析(静态字面量,构建不触发
      导入),SARIF driver 的硬编码 `"1.0"` 改 `_tool_version()` 惰性导入
      (此前导出的 SARIF 工具版本永久脱节);③ **fresh-clone 可复现**:
      report_theme.py / mxss_verify.py 正式入库(此前 mxss_verify 靠本地
      info/exclude 游离于版本控制),.git/info/exclude 里的 `.workbuddy/`、
      `benchmark/results/*_log.txt`、`/_*` 全部升入共享 .gitignore,dev/ 下
      沿用 `_ 前缀不入库` 约定(`/dev/_*`);④ **仓库根减负**:两份中文过程
      报告(288KB+32KB)git mv 进 `docs/archive/`;⑤ **CI**:benchmark-full 与
      nightly-gate 补 `.[async]` extra(全量矩阵含 async 引擎,`. [dev]` 单装
      会在新 runner 上缺 aiohttp);⑥ **依赖漂移**:esprima pyproject 侧对齐
      `>=4.0`;⑦ README 开头 36 条特性墙折叠进 `<details>`,落地页恢复
      "定位→安装→快速开始" 阅读动线。验证:干净 venv(独立 pip)editable
      安装 + `xssentinel --help` 入口点 + SARIF 版本 1.0.0 + `--self-test`
      端到端烟测全过。遗留决策:LICENSE 选 MIT 是默认值,若需 Apache-2.0/
      专有许可请替换文件与 pyproject 字段。
      **续(同日)**:补齐 CONTRIBUTING / CHANGELOG / SECURITY 三件套
      (SECURITY 的举报联系方式留待仓库归属者填写);pyproject 补 classifiers。
      **lint 基线决定不清理**:全仓库 ruff 实际 212 条(此前只查过改动文件
      得 12 条),其中 scanner*.py 的大量 F401"未用导入"是 Mixin 运行时引用
      的故意导入、E402 多为 sys.path 垫片——盲目 --fix 会让扫描器核心运行时
      NameError,零功能收益换核心风险,记账为有意基线。

- [x] **187 同类竞品吸收第二轮(dalfox v3 全 release 线 / nuclei XSS 模板族 /
      ezXSS / XSS Hunter / DOM Invader / XSStrike / kxss 系全盘调研 → 两项
      测量化落地)**。调研先纠讹传:dalfox 无原生 sitemap/robots 输入(社区靠
      gospider 管道)、tomnomnom/kxss 与 s0md3v/BruteXSS 仓库已 404、kxss 原版
      只测 4 元字符(13 字符是 Emoe 分支)。真实能力级差距按"竞品有 × 排除清单
      没有 × 可测量"筛出两项,均落在"判定有测量支撑"主线上:
      ① **postMessage 探针改为攻击者源投递(DOM Invader origin-spoof 的
      在桩实现)**:原 harness 以 `origin = location.origin` 派发合成消息 ——
      带 origin 校验的 handler 照样触发 sink 被判可利用,而浏览器永远禁止
      跨源消息冒充本源,这是一类潜在 FP。改为只派发攻击者可达源
      (`https://attacker.example` + 沙箱 iframe 的 `null`),有效 origin 校验
      的页面测量为沉默;`window.onmessage` 赋值形态经属性 setter 一并覆盖;
      postMessage 命中的 detail 显式写明攻击者源语义。
      ② **CSP allowlist → 第三方 gadget 执行链(nuclei csp-bypass 模板族 /
      renniepak CSPBypass 的吸收)**:`csp.SCRIPT_GADGETS` 表(35+ 条 Angular/
      Vue/JSONP)从 Phase 20 起只作静态建议("does NOT execute"),现在
      `register_gadget()`(带 `__SRC__` 占位,测试/新 CDN 可插)+ `analyze()`
      纳入注册 gadget(相关性门与 is_strict_inline 都读它)+ `gadget_chain_
      relevant()`(gadget 是唯一脚本路由才尝试)+ 双引擎接线:sync
      `_try_csp_gadget`(先 verify_semantic,JSONP 形态因 token 骑在 src
      属性上静态诚实沉默、由 verify_headless 补测)、async Phase-100 对位块
      (静态 machinery 确认,JSONP 留给 sync+headless,不对称已记账)。
      打标契约:表内 8 条 Angular/Vue gadget 外层单引号改双引号,否则
      `verifier.mark` 的 `alert('tok')` 会嵌套产出坏 JS。attempt 上限
      2/(url,param);无 gadget 主机的页面零行为变化。测试
      `tests/test_csp_gadget_chain.py`(9 例,含本机靶场 JSONP gadget 真
      Chromium 执行确认 = EVIDENCE_BROWSER_EXECUTED 的全链测量)+
      `tests/test_dom_postmsg_origin.py`(3 例,行为级,含"origin 校验
      handler 必须沉默"的 FP 回归断言)。
      回归:静态层 285、DOM 引擎 42+4 skip、async 56、红队 15/15、
      benchmark quick 双引擎 F1=1.0 FP0/FN0、range4 门禁 TP2/FP0/TN2/FN0
      (首跑 neg 例 180s 超时为重负载瞬时伪影,复跑 8.4s 全绿)。
      全量分批门禁 **142/144 文件绿(3055s)**,两个失败均已定性:
      test_layer_registry_parity(真回归——`L7_csp_gadget` 忘注册进
      coverage.LAYERS,门禁抓到即修,复跑 11 例全绿)与
      test_benchmark(双 attempt TIMEOUT,签名与
      dev/WEDGE_test_benchmark_20260927.md 完全一致:L1 探针 connect
      挂起超 settimeout、门禁后单文件重跑 30 分钟不返回 —— pre-existing
      环境 wedge,按"未验证"记账)。range3 runner 三次失败均在**服务器
      起靶健康检查**(GET / 读超时;server.py 与 HEAD 逐字节一致,失败先于
      任何扫描器代码)= 同族环境劣化,同样按"未验证"记账。

- [x] **188 同类竞品吸收第三轮(187 记账的剩余差距 → 四项落地)**:
      ① **async JSONP gadget 对位补全**(收掉 187 的已记账不对称):静态
      不确认但 `gadget_chain_relevant` 且**浏览器真实可用**时,async 发出
      candidate finding(EVIDENCE_NO_BROWSER / low),由 Phase-183 的
      `scan()` 外层 wrapper 做 headless 确认/否证 —— confirmed 升
      browser-executed/high,refuted 落 browser-refuted/low;无浏览器则
      保持沉默(与 sync-without-headless 语义逐字一致,不发投机 finding)。
      本机靶场实测 wrapper 全链确认。
      ② **kxss 式反射元字符 triage 落进 finding/报告**(kxss 只为打印这个
      而存在,我们算了却只做内部信号):`reflection_profile.triage_line()`
      (`raw="'><>()=/;\` | stripped=< | encoded=&`)经 `_record` 挂到
      confirmed finding 的 `reflected_meta` 字段 —— JSON 报告自动携带,
      HTML 报告在 severity 单元格的 evidence 元数据区渲染。纯元数据,
      判定语义零变化。
      ③ **盲打回调收集面**(ezXSS/XSSHunter 标配):`blind_oob` 家族首位
      新增 collector 载荷(esprima 校验合法;`mark()` 不误伤)—— cookie/
      localStorage/sessionStorage/referrer/URL/UA/DOM 片段一次带全,分段
      截断防爆 URL;`SelfHostedListener` 开始记录每个 beacon 的 query
      (`hit_query()`,poll 契约不变);`collect_oob` 把参数名(不泄露值)
      写进 detail、原始 query 截断进 `proof.callback_query`。盲层每
      (url,param) 只注入一条(`blind_bases[0]`),collector 放首位即
      一发全收。
      ④ **`--wayback` CDX 输入源**(gau/waymore/ParamSpider 管道的一键化;
      dalfox 也没有,差异化项):`core/wayback_import.py` —— 域名或
      域名+路径前缀 → CDX 查询(`fl=original` + `collapse=urlkey` +
      `filter=statuscode:200` + limit 安全带),wayback 改写前缀防御性
      剥除,junk 行/非 http(s) 过滤,scope 分区与 --sitemap 逐字同款
      (操作者点名的主机才是授权)。CLI 两条引擎共享一条接线。
      测试:`tests/test_phase188.py` 8 例(triage 三态 + finding 携带、
      listener query 记录、collect_oob 端到端、async JSONP wrapper 确认
      + 无浏览器沉默回归)+ `tests/test_wayback_input.py` 9 例(CDX URL
      构造/解析/去重/上限/前缀剥除/空档案 + 一条真 HTTP 回环 + CLI flag)。
      受影响面 10 文件分批全绿;range4 门禁 TP2/FP0/TN2/FN0、benchmark
      quick 双引擎 F1=1.0 FP0/FN0;ruff 全过。全量分批门禁
      **143/146 文件绿(7810s,loopback 劣化致首跑普遍超时、重试全绿)**:
      4 个文件首跑 TIMEOUT/失败、重试通过(test_async_budget* /
      test_async_headless_verify / test_api_ai_report —— 环境形态);
      两个**真回归被门禁抓到即修**——test_coverage_matrix_parity
      (`L7_csp_gadget` 只注册了 coverage.LAYERS,没进 layer_coverage
      的 COVERAGE 矩阵,已补)与 test_evidence_coverage(`_record` 改
      `Finding(**_fkw)` 变量构造踩了 pass-through 站点钉子,改回字面量
      构造 + 事后附加 reflected_meta),两文件修复后复跑 18 例全绿;
      test_benchmark 仍是文档化环境 wedge,按"未验证"记账。

- [x] **189 同类竞品吸收第四轮(凭据 egress + 判定粒度 + 语料现代化 + 输入面)**:
      调研先纠一处自我认知:187/188 之后**剩余差距不在载荷库,而在"谁拿到我们的
      凭据"和"我们对 CSP/sanitizer 的描述是否还是 2020 年的"**。四项:
      ① **`core/egress.py` 凭据守卫**(对标 Dalfox GHSA-mph2-gf5w-6f9f 修复):
      本机实测 requests 2.32.5/urllib3 2.6.3 跨源 302 **只按 host 字符串**剥
      `Authorization`/header 形 `Cookie`(`localhost→127.0.0.1` 算跨、
      `h:8080→h:9090` 不算),自定义 `X-Api-Key` 与无 domain 的 `--cookie`
      原样送达;aiohttp 3.13.3 header 与 jar cookie **全送**。规则一条:凭据只跟
      "操作者点名的源"走。sync 落在 `GuardedSession.send`(requests 在 `send`
      里逐跳重入,且 jar→header 的物化发生在 prepare 阶段,故 `request()` 前
      删头会被 `resolve_redirects` 重新装上);async 落在 `_session_kwargs()`
      双机制 —— `on_request_redirect` 剥 header(aiohttp 把同一 header dict
      转发到每一跳)+ **`CookieJar.filter_cookies` 子类门控**,因为实测
      aiohttp 是在**构造 hop 时**套 jar,晚于 redirect hook,只剥 header 会漏
      cookie(`cookies=` 与 `cookie_jar=` 互斥 → 操作者 cookie 改为 seeded jar)。
      另 `llm_pool` provider `Bearer` key 改 `allow_redirects=False`(3xx 落既有
      失败分类)。重定向仍跟随、body 仍解析:判定语义零变化,`Browser-shaped`
      header 清单保证跨源链不像扫描器。
      ② **CSP 交付家族粒度**:`script-src-elem`/`script-src-attr` 对各自投递形态
      是**替换**而非追加;原实现四处只读 `script-src`,两个方向都错(
      `script-src 'self'; script-src-attr 'unsafe-inline'` 被整体判"内联全禁"
      → 反射 onerror 被否证 + 预算切早停 = FN;`script-src https://cdn…` 无反
      射 `<script>` 被判可执行 = FP;`script-src` 的 nonce 越界吃掉
      `script-src-attr` 的 `unsafe-inline`)。新增 `SCRIPT_FAMILIES` /
      `family_sources` / `family_allows_inline` / `inline_blocked(header, family)`,
      `analyze` 的 gadget/通配符扫描改读三族并集并按家族给 inline 绕过形态,
      `verifier` 事件处理器分支走 `_csp_blocks_attr()`、原文兜底分支改"两族
      都封死才否证";`_CSP_BLOCK_RE` 退役(它只会漏 `script-src https://cdn`)。
      ③ **净化器语料现代化**:版本线 2020→三段修复线(<2.0.8 / <3.1.3 / ≤3.4.15,
      编号从厂商 advisory API 实拉,25 条、latest 3.4.16),2026 年全部 advisory
      的利用面是**配置项**,故补 IN_PLACE / CUSTOM_ELEMENT_HANDLING /
      SAFE_FOR_TEMPLATES / setConfig() 持久化 / USE_PROFILES / ADD_ATTR 里的
      `on*`(high)/ ADD_URI_SAFE_ATTR / ALLOWED_URI_REGEXP / RETURN_TRUSTED_TYPE;
      表结构改 dict + `patterns` 元组,顺带修掉"横幅与 npm 路径两种形态各报一次"
      的重复计数。`docs/OPTIMIZATION.md` 复核:它自称待做的 3.1/3.2 **早已完成**
      (requirements.txt 现在就是 `-e .[dev,async,ast,api]` 一行委托),
      竞品"退出码四态"也已有 0/1/3 三分 —— 按该文档自己定的规矩逐条 grep 过。
      ④ **`core/sourcemap.py` source map 摄取**:`//#`(legacy `//@`、块注释形、
      `data:` 内联形)→ `.map` → `sourcesContent` 未压缩源码进既有 js_miner
      通道;可读回另记 `source_map_exposed`(low,`evidence_class` 用
      browser-unavailable —— 证据是取回并解析了文件,不是浏览器)。硬限制:
      每脚本最多取一个 map、**引用指向别的源就不取**、非 JSON/超限 body 不炸
      挖矿;async 侧披露发现经 `_crawl_mine_endpoints(..., findings=)` 出参回传
      (签名不动,两个既有 async_wiring 测试原样通过)。层名沿用 `L9_js_miner`,
      不新增未注册层(187/188 两次被门禁抓到的同一课)。
      测试 63 例:`test_egress_guard.py` 15(双 origin 真回环,同族 header
      两侧都断言 + 授权边界三例)、`test_csp_families.py` 18(含"同 header 下
      `<script>` 被否证而 `onerror` 被确认"这对孪生断言)、
      `test_sanitizer_modern_corpus.py` 13(含"加固页必须沉默"反向对照)、
      `test_source_map_ingestion.py` 17。
      **同日续:`--stop-at-cross-origin` 授权边界** —— 把同一条规则从"剥凭据"升级为
      "不投递载荷":页面 `Location:` 指向未点名源时请求根本不发出(调用方拿到 3xx 本身,
      运行末尾列出被拒绝的跳转,"0 findings" 不得暗中意味着"停在别人的源上没看")。
      实现利用 requests 的消费方式 —— `Session.send` 以 `[resp for resp in gen]` 取
      最后一个 yield 当响应,故 `resolve_redirects` **不 yield 即停止跟随**,无需合成
      响应、不碰私有 API。CLI 端到端实测:默认关时一次扫描 40+ 探针落到第三方 loopback
      源(落地请求确认无 `X-Api-Key`),开启后该源 0 命中;同域跳转照常跟随带凭据。
      async 不对称已记账:aiohttp 跳转循环在 `ClientSession._request` 内部,实测
      `on_request_redirect` 改不了下一跳目标,故 async 只做到剥凭据,CLI 用
      `_warn_async_partial_flags` 显式说明而非假装支持。
      **SSR hydration state 评估后决定不动**:挖矿侧 `__NEXT_DATA__` 的
      `"path": …` 走的正是同一 extractor;当污点源会改判定语义,要动得先有
      Chromium oracle 对照测量(见 docs/OPTIMIZATION.md 3.6)。
      **门禁(2026-10-02)**:全量 sync 矩阵首跑 **TP113 FP1 TN78 FN0 ERR0**
      (f1=0.996)——唯一 FP 是 `neg-sanitizer-01`,**归因:靶场时基陈旧,不是
      判定错误**。该 safe twin 以"DOMPurify 3.0.6 = 当前版本 + textContent
      安全汇聚"表达干净,而 3.0.6 自 CVE-2024-47875(嵌套 mXSS,3.1.3 才修)起
      确为易受攻击版本 —— 发现为真。故改靶场(3.0.6→3.4.16;`integrity` 必须
      留着,摘掉会撞上 sri_bypass"跨源脚本无 SRI"high,把一个 FP 换成另一个
      FP),不改判定;`tests/vuln_server.py` 两处同样以 3.0.0 代表"现代版本"的
      fixture 一并升 3.4.16。定点复测 pos/neg-sanitizer-01 = TP/TN。
      修复后 **async 全量矩阵 TP108 FP0 TN74 FN0 ERR0(f1=1.000,与本仓
      既有 async 基线逐项相同,零退化)**;sync 全量复跑
      **TP113 FP0 TN79 FN0 ERR0(f1=1.000)**
      (`benchmark/results/phase189_full_sync_final.json`)——双引擎全量矩阵
      同轮双双回到零 FP 零 FN。
      其余各门:benchmark quick 双引擎 F1=1.0 FP0/FN0;range4 双引擎门禁
      TP2 FP0 TN2 FN0(browser-confirmed 12/12 与 23/23);红队常驻回归 +
      本轮四个新测试文件(60 例)+ sandbox 保真 95 例全过;受影响面定点批次
      243(sync 传输/认证/stealth)+ 35(async)+ 58(crawl/层注册奇偶)+
      156(CSP/verifier)+ 134(report/卫生/pyflakes 未定义名)+ 59(PoC·
      nuclei 回放)+ 125(CSP/verifier 复跑)全绿;改动文件 ruff 零基线全过。
      **未跑**:全量分批测试门禁(`tests/run_all_batched.py`,历史 5000-7800s)
      —— 按"未验证"记账,不当已验证。
      **授权边界续跑门禁**:默认路径(开关关)复跑全量 sync 矩阵
      **TP113 FP0 TN79 FN0 ERR0 f1=1.000**(`phase189f_full_sync.json`,与前一跑
      逐项相同),quick 双引擎亦 F1=1.0 FP0/FN0;边界三例测试 + CLI 端到端探针
      (`dev/_p189f_e2e.py`,不入库)实测 ON/OFF 差异;requester 路径定点批
      178 passed / 21 skipped(loopback 健康位)。
- [x] **190 门禁可信度:先量尺子,再拿尺子量**:评价本项目时发现一类
      和"检测面"无关、但会让所有精度结论失去意义的问题——**门禁的尺子本身
      烂掉了,而文档还在引用旧刻度**。四项:
      ① **push 精度门禁看不见 43% 的检测面**:`--quick` 的 `per_class=5` 在按
      上下文字母序轮转时中途撞上限,每次 push 只测 5 正 + 5 负,`html_element`
      (48 正 + 34 负)被测量 **0 次**;且 `FPR>20%/recall<50%` 在 10 例规模上
      **容忍 1 FP + 2 FN 仍绿灯**。切片改为"每个 `(ground_truth, context)` 一条"
      = 64 例(覆盖全部 36 正 / 28 负上下文),新增 `--strict-gate`
      (FP0/FN0/**ERROR0**——"没测到"不能让门禁显得"测过了")。
      **本机最坏口径实测双引擎零容错过**:sync TP36/FP0/TN28/FN0/ERR0 370.3s,
      async TP36/FP0/TN27/FN0/ERR0(1 SKIP)267.3s,产物入库
      `benchmark/results/phase190_quick_{sync,async}.json`。
      ② **CI 从来没有量过 async**:push 门与 `benchmark-full` 都只跑 sync,而
      本项目记录在案的每一次"async 漏了 sync 的修复"(concat 重试 /
      content-type 降置信 / JSONP gadget 不对称)恰好都从这个缝里钻过去。
      现 push 门双引擎 + `--strict-gate`,`benchmark-full` 补 async 臂。
      ③ **文档刻度失真**:`ci.yml`/`CONTRIBUTING.md`/`OPTIMIZATION.md` 把 `--quick`
      写成"98 例"(实际长期 10 例),`run_benchmark_batched.py`/`run_dalfox_only.py`
      把矩阵写成"98 用例"(现 192)。按本项目 1.1/3.5 反复自省的同一课
      ("文档写完没回头核对")补了反制机制:`tests/test_quick_gate_slice.py` 6 例,
      其中一条断言**文档里写的切片数字 == 代码实际产生的数字**,陈旧字面量显式禁用。
      ④ **工具自身攻击面**(扫描器 = 会替你发请求、带你的凭据、对外开 HTTP 的进程):
      `--host` 的 help 明写"use 0.0.0.0 to expose externally"而 `--api-key` 可选
      (`_check_api_key` 未配置即放行)——这样起出来的是"任意 URL 抓取预言机 +
      漏洞结果泄露点",现在这种组合启动即告警(不拒绝:反代做认证是合法部署)。
      审这条时又量出一个**功能级 bug**:Phase 70 的 `Host` 白名单无条件生效,
      于是 `--host 0.0.0.0 --api-key X` 对**每个**合法远程客户端返回 403
      (`Host: 192.168.1.5:8000` → `cross_origin_blocked`,实测),宣传的对外部署
      根本不可用。改为"配了 key 时 Host 白名单让位于密钥,没配 key 时照旧全量生效",
      `Origin` 那一半(跨站状态变更)保持无条件。
      两条都带反向对照防"放宽无边界":无 key 同样请求仍 403、有 key 但外来
      Origin 的 POST 仍 403、有 key 服务缺 key 头仍 401。
      **顺带纠自己一个错**:写告警注释时先入为主断言"直接打 IP 的客户端 Host 是
      本地的、所以同源防御挡不住",实测方向相反(它会被 403)—— 注释已按实测重写。
      另:Phase 70 防御对**浏览器**威胁模型是对的(页面伪造不了 Host/Origin),
      这次不是推翻它,是给它划清适用边界。
      验证:新增 14 例(`tests/test_quick_gate_slice.py` 切片契约 6 +
      `tests/test_p27_api.py` 部署与告警 8,含反向对照)与既有 API 套件同跑
      共 93 passed;改动文件 ruff 全过;
      `ci.yml` YAML 解析并复核三条作业的安装 extra / timeout / 步骤命令。
      **未做**:全量 192 例矩阵本轮未复测(单引擎 12~25 分钟、双引擎更久),
      所以 `--strict-gate` 只挂在 64 例切片上,**全量矩阵刻意不加严**——
      没量过的东西不进门禁。
- [x] **191 async 引擎 Mixin 化(纯移动,且"纯移动"是被量出来的)**:
      `async_scanner.py` 3124 行 → **1534 行核心** + layers 991 + crawl 321 +
      common 270 + verify 136。它是全库最大文件、是当年拆掉的 scanner.py 核心的
      2.5 倍,违反本项目第一条约定;而"async 漏了 sync 的修复"已付过两次账。
      **等价性标尺** `dev/_p191_baseline.py`:42 个方法的 `inspect.getsource`
      逐个哈希存档 → 搬完 25 个换归属、**源码逐字节相同**、无方法丢失;被裁掉的
      模块级名字逐个验证"全仓零外部引用"才允许消失(标尺自身也修过一次假阳性:
      `[^#]*` 跨行正则造出 5 个假"悬空引用")。`_EGRESS_JAR` **刻意不再导出**
      (`from x import name` 是值拷贝,做别名会让"重置缓存"的测试打在影子副本上)。
      **行为侧**:64 例 async 切片逐用例 verdict + findings_count 与拆分前全等,
      请求数 7415 → 7415;110 例 async + 守卫 + 结构对账全绿;`ruff check .` 零告警。
      **三个按文件路径锁调用点的守卫**(`test_async_wiring` 单文件、
      `test_layer_accounting` SITES、`test_evidence_coverage` committed 名单)拆完
      全部**响亮地红**——正是该有的行为;逐个改成遍历引擎全部模块,各加一条前提
      断言(文件数==5 / 每文件非空 / 必须找到调用点)防空转。
      **本轮唯一改逻辑**发生在等价性取证**之后**,标尺重跑如实报出该方法哈希变化:
      修 Phase 189 遗留的 2 红 —— `test_async_hidden_param_mining` 的 `_FakeAiohttp`
      缺 `CookieJar`/`TraceConfig`,且失败位置随测试顺序漂移(`_EGRESS_JAR` 全局缓存
      被真 aiohttp 填过就后移),补桩 + 隔离缓存 + 新增污染方向守卫;
      `sourcemap.disclosure()` 改返回完整 kwargs,两处 emit 站点退化为可审计的
      `Finding(**fields)` 纯转发(层级仍只声明一处,判定语义零变化)。
      **未验证**:改逻辑之后那次 64 例 async 复跑卡在本机 loopback wedge(15 分钟
      停在 10/64),已终止并清理子进程,按"未验证"记账——该形状变更由
      `test_source_map_ingestion.py` 17 例(含真服务器端到端)覆盖。

- [x] **192 MCP stdio server + PortSwigger 事件语料补齐(竞品吸收收官)**:
      ① **`--mcp` / MCP stdio server**(dalfox v3 已有,2026 年安全工具给
      LLM Agent 当工具的集成面;此前只有 REST `--serve`):`api/mcp_server.py`
      —— JSON-RPC 2.0 逐行 stdin/stdout,实现协议稳定核心(initialize 版本
      协商 / notifications 静默 / tools/list / tools/call / ping;未知方法
      -32601、坏 JSON -32700、非对象 -32600),stdout 永远只走协议、诊断只走
      stderr。单工具 `xssentinel_scan`(url/method/data/headers/cookies/
      max_payloads/headless/timeout),同步驱动与 REST API `_scan_worker`
      同款扫描路径,finding 压缩交付(type/severity/confidence/
      evidence_class 保留、proof/PoC 摘除、长字段截断 500、上限 200 条)
      —— Agent 的上下文窗口是要保护的资源。**找零结果是成功、扫描失败才
      isError**。测试 11 例含真子进程 stdio e2e(spawn
      `python -m xssentinel --mcp` 握手→调用→回环靶场 finding)。
      ② **PortSwigger 事件处理器语料缺口**(自家参照基准量出的账:
      no_interaction events 23.1% / tags 71.4%):新语料家族
      `portswigger_events` 48 条 —— 40 个缺失 no-interaction 事件
      (hashchange/pageshow/animation+transition 族/media 族/
      **onsecuritypolicyviolation 自触发:页面 CSP 拦掉随行 `<img>` 即执行,
      与 187 的 CSP gadget 链协同**/beforematch/slotchange…)、6 个缺失标签
      (address/b/span/br/camera/slot 作宿主)、other 组 6 事件
      (beforescriptexecute 族/SMIL)。**无位移纪律**:不动 205 条
      `html_element` 主族(步长采样点不变,既有确认路径零扰动),新家族由
      sync `_build_candidates` 与 async `_CROSS_CONTEXT` 各取样 2 条、排在
      主队之后只花剩余预算;测试钉住两个家族大小。
      结果:no_interaction **events 23.1%→100%、tags 71.4%→100%、
      other events 57.1%→100%**(other 组 x/teleport/xyz 等异形标签留缺,
      记账不追)。
      门禁:定向 97 例 + 语料 5 例 + MCP 11 例全绿;benchmark quick 双引擎
      strict 切片 TP36/FP0/FN0 F1=1.0;ruff 全过。全量分批门禁
      **151/153 文件绿(3071s)**:test_passive_proxy / test_sitemap_input
      首跑失败重试绿(环境慢形态);两个失败一为文档化 test_benchmark
      wedge(照旧"未验证"记账),一为 **test_async_budget —— 并发会话
      189/191 的遗留缺陷而非本轮回归**:`_session_kwargs` 无条件子类化
      `aiohttp.CookieJar`(189 egress 守卫),而该文件自己的 aiohttp 桩缺
      `CookieJar`/`TraceConfig` 且未隔离 `_EGRESS_JAR` 缓存 —— 正是 191
      在 test_async_hidden_param_mining 修过的同款问题(另一个文件)。
      已按同一模式修复(补桩 + 缓存隔离,连带 file 内注释),复跑
      test_async_budget + test_async_hidden_param_mining + test_egress_guard
      3/3 文件绿(616s)。语义测量仍由真 aiohttp 的 test_egress_guard 承担。

## 环境配置

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(2026-09-25 实测
  129 个 test_*.py 文件;裸跑单进程会卡死,必须分批 —— `test_async_budget.py` 在本机
  会挂满 2×540s 预算,按"未验证"记账而不是当回归)
- benchmark: benchmark/ 目录;报告产物: report.html
