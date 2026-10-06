<!-- agenthub:generated source=.agenthub/PROJECT.md at=2026-08-30T13:12:04.248 hash=ede70d8e1bf1 -->
# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

## 规则约定

- scanner.py 已 Mixin 拆分(2026-10-05 实测:核心 1869 行 + layers 769 + crawl 406 + stored 579 + findings 216):新增能力进对应 Mixin,不堆回主文件
- async_scanner.py 已同样 Mixin 化(2026-10-05 实测:核心 1618 行 + layers 1006 + crawl 321 + verify 136 + common 270,Phase 191):新增 async 能力进对应 Mixin,不堆回主文件;搬代码与改逻辑绝不混在同一轮
- fix_advice.py 数据化(2026-10-05 实测:127 行引擎 + JSON 语料):改建议优先改语料
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
      **同日续(环境债清偿):两个长期"未验证"项全部根因修复并验证** ——
      ① **test_benchmark wedge 结案**(原记账 187/192 两轮):Phase 179 迁
      端口时 `tests/benchmark.py` 的 `BENCH_PORT`→18899 但 `BASE` 仍指 8899,
      服务器健康监听却零流量,扫描器连向死端口、SYN 被安全软件静默丢弃 →
      connect 挂起超 settimeout。修为 BASE 从 BENCH_PORT 派生(漂移结构上
      不可能);复测 **35 passed in 13.86s**(此前每次 540s×2 超时)。
      ② **range3 起靶 wedge**:HTTP/1.1 keep-alive 下 `_send` 缺
      Content-Length(c0cbb45),requests 读 body 到 EOF 必挂;修复后 runner
      完整跑通,sync **TP20/FP0/TN6/FN0** + async **TP18/FP0/TN6/FN0/SKIP2**,
      每案例约 1s,双引擎零误报零漏报。dev/WEDGE_test_benchmark_20260927.md
      已改写为结案记录(含"connect 挂起先查客户端连的是谁"的经验)。

- [x] **193 HPP 探针 + 交互事件可测量化(竞品吸收第五轮)**:
      ① **HPP 参数污染探针**(dalfox `--hpp`):同参数投递两次 —— 首现 benign、
      次现 payload;后端取首/取尾不一致,只查首次出现的过滤器看到 benign 放行,
      应用渲染的却是 payload。sync `_try_hpp` + async 对位块,双门禁
      (WAF 存在 + 标准梯子未确认),query 位本轮,上限 2/(url,param),确认走
      标准 verify_semantic(transform=["hpp"],EVIDENCE_MODEL)。层名 L2_hpp
      一次注册两处(coverage.LAYERS + layer_coverage 矩阵,187 的教训)。
      测试:首现过滤服务器(sync 直调 + async 专用桩驱动 _probe_param)+
      取首值后端反例 + (url,param) 去重。
      ② **requires-interaction 事件可测量化**(该组原覆盖 15.4%,README
      方法论里它"仅参考"的根因是不可测量):`interaction_events` 语料 27 条
      (pointer/mouse/clipboard/drag/touch/submit/select,宿主轮换)+ DOM
      引擎 `interaction_dispatch_js`(token/marker 承载元素上派发有界事件集,
      isTrusted=false 只会欠测不会过报)+ 双接线(verify_headless 派发后判
      dialog;dom 引擎每探针派发后重读 sink 日志,hit 带 via='interaction'
      并写进 detail)。复测 requires_interaction events **15.4%→49.0%**
      (剩余为 pause/reset/drag 单发等长尾,记账不追)。
      **门禁抓到 12/11 FP,根因即修**:派发 JS 自身含 NEEDLE 行,eval 钩子把
      派发器源码记成页面发起的 eval 命中 —— strict 切片 12 个"反射原始+浏览器
      防御"neg 用例全数翻红。修法沿用 Phase 162 契约(派发前后抬/清
      `__xss_dom_harness` 旗标,旗标只护 eval 钩子、交互期 sink 命中不受影
      响),复测双引擎 **TP36/FP0/FN0 F1=1.0**。
      验证:phase193 10 例(含 2 例真 Chromium 交互确认)+ 跨 phase 106 +
      async/MCP 46 + stored/static 62 全绿;range4 门禁过;ruff 全过;
      全量分批门禁随跑随记(_regress_phase193_full.log)。

- [x] **194 stored-XSS dialog 闭环 + session 失效策略(竞品吸收第六轮)**:
      调研清单上最后一个"需自查"项落地。① **stored-dom dialog 通道**
      (dalfox --sxss waitdialog / nuclei waitdialog 语义):自查发现
      Phase 152 的 stored-dom 已有"注入→真浏览器回访→sink 证据"闭环,但
      纯 `<script>alert('token')</script>` 存储载荷执行时**不经过任何被钩
      sink** → 漏报。`analyze()` 增加显式 opt-in 的 `dialog_token` 参数
      (dialog 消息含 token 即记 sink='dialog' 命中,仅作 sink 命中为空时
      的 fallback —— sink 命中指名具体 sink,是更强证据)。**流程特异性是
      硬约束**:marker 只在调用方注入的代码里时 dialog 才是执行证明;URL
      源探针(alert(location.hash) 只是显示)绝不能开,默认关。async 无
      stored 流程(已在 _ASYNC_SYNC_ONLY_FLAGS 文档化),无需对位。
      ② **--session-check REGEX + --on-session-loss {relogin,abort}**
      (dalfox 对位):失效探测从 401/403/登录重定向扩展到**响应体正则**
      (200 页写"请先登录" defeating 状态码检查;正则未配置不读 body,钩子
      里零开销);abort 策略经 BudgetExhausted 走既有优雅停机(findings
      保留、原因记账),keep_alive 的吞异常路径显式放行 BudgetExhausted。
      测试 9 例:正则四态(命中/未命中/未配置/状态码并存)、abort 经钩子
      与 keep_alive 双路径抛出、relogin 不抛、CLI flag 存在、纯 alert 存储
      载荷真 Chromium 经 dialog 通道确认(EVIDENCE_BROWSER_EXECUTED)。
      顺带修测试替身契约:_FakeEngine.analyze 增补 dialog_token 形参
      (TypeError 被扫描器的 continue 吞掉曾伪装成"未确认")。
      全量分批门禁随跑随记(_regress_phase194_full.log)。

- [x] **195 GraphQL introspection 输入面 + 交互事件长尾(竞品吸收第七轮)**:
      ① **`--gql ENDPOINT`**(inQL 对位,库存清单最后一个命名输入面缺口):
      `core/gql_import.py` —— 标准 introspection 查询(响应 8MB 安全带)→
      提取 String 型 mutation 参数 / input-object 字段 / query 参数 / 字段名,
      按"写入侧优先"排序去重(上限 200),合并进挖矿词表(cli_runner 三行
      合并,--param-wordlist 同款),端点本身成为扫描目标;GraphQL errors
      /非 JSON/无 queryType 显式报错。测试 8 例(fetch 注入解析/排序/去重/
      上限/错误面 + 一条真 HTTP 回环 + CLI flag)。
      ② **交互事件长尾**:dispatch 事件集 25→~60 型(键盘/编辑/媒体状态/
      toggle/指针捕获/生命周期),语料 27→63 条,requires_interaction
      events **15.4%→73.1%**;剩余 28 个(设备传感器/导航生命周期/prompt
      类/Safari 手势/私有 webkit)不可诚实派发,记账不追。
      门禁:定向 26+86 全绿、benchmark quick TP36/FP0/FN0、ruff 过;
      全量分批门禁 **155/156 文件绿(7481s)** —— 唯一失败
      test_async_headless_verify 双跑 TIMEOUT 为纯环境慢(全桩套件,
      与本轮改动零交集;门禁后单文件复跑 **19 passed in 0.91s**)。

- [x] **196 浏览器渲染输入发现 + HPP body 位(竞品吸收第八轮)**:
      ① **`--discover`**(库存清单最后一个命名缺口:"无基于浏览器渲染后的
      动态输入发现"):`DynamicDomAnalyzer.harvest(url)` 渲染目标一次,
      收割 LIVE 输入面 —— SPA 表单字段名(input/textarea/select/button)
      合并进挖矿词表(`--param-wordlist` 同款),页面自己 fetch 的
      **同源** API 端点(performance resource entries,严格同源过滤,
      176l 授权纪律)作为附加目标在主目标后扫描(上限 10);认证状态
      随行,全部 best-effort 降级不炸扫描;async 经
      _ASYNC_SYNC_ONLY_FLAGS 文档化不支持。`_normalize_harvest` 纯函数
      单测(去重/上限/大小写同源/分片剥除/垃圾降级)+ 真 Chromium 渲染
      收割测试。② **HPP body 位补全**(193 记账的"query 位本轮"):
      form 体以裸 urlencoded 字符串 + 显式 Content-Type 重复参数(dict
      无法携带重复键),JSON 载体仍归 pre-encode 管线;async 对位同形状。
      测试:body 首现过滤正例 + JSON 载体跳过反例。
      **后续修复(并发会话,0814661/df64e29,均为本条目代码的真缺陷)**:
      sync `_try_hpp` 曾硬编码 `param_in="query"`(body 位探针也记 query)
      —— poc.py 按 param_in 造重放,body 位的 PoC 全部打在错误位置;
      两处断言本身跑不过(同源检查比较对象写错、`Scanner(json_body=)`
      构造参数不存在,应为 `sc.json_body` 属性)。已修 + async body 位
      专项回归锁(test_async_phase196_hpp_body_parity.py,线上/字段
      双半断言 + 取首值后端反例)。

- [x] **196b 外部效度对照 + CSP 投递通道判定 + API 前端门对齐(竞品吸收第八轮)**:
      ① **把"能不能打赢同类"从声称变成测量**(补 OPTIMIZATION 1.0 长期挂着的缺口):
      `benchmark/run_cross_tool.py` 让 XSSentinel / dalfox v2.13.0 / nuclei v3.9.0 在
      **同一批目标**上跑 60 例分层确定性切片(64 个 `(ground_truth, context)` 族各取一条)。
      终局 **XSSentinel TP35/FP0/TN24/FN1 f1=0.986(346s)**,dalfox TP26/FP1/FN10/ERR1
      f1=0.825(1173s),nuclei TP26/FP0/FN10/ERR1 f1=0.839(49s)。产物
      `benchmark/results/phase196_cross_tool.{json,md}` 带工具版本 + 逐例矩阵 +
      `engine_fingerprint_start/end`(我方每条用例都新起子进程重新 import 引擎,
      树在动的时候逐例数字无法归因 —— 本轮两次作废的 run 就是靠它确认的)。
      环境结论更正:GitHub API/raw 与 goproxy.cn 可达(**`go install
      hahwul/dalfox/v2` 装得上**,`_find_tool` 本就查 `$GOPATH/bin`),
      不可达的只有 github.com release 资产(dalfox v3 Rust 版拿不到)。
      ② **先修尺子,再谈结论**(四处失真,每一处都会伪装成"检测缺口"):预算
      10/6 vs 门禁 14/12 → 改 `runner.py` 单一定义;目标拼成 `?q=test` 丢掉
      `sub.localhost` host 别名与 6 条用例的 per-case 旗标(`--oob self` /
      `--audit-xs-leaks`)→ 共用 `_build_target_url` + `_case_extra_args`,
      **首跑 3 个"我方 FN"里 2 个因此是尺子造成的,修完变 TP**;子进程按本机
      GBK 解码,第三方输出一个非 GBK 字节就在 `subprocess.run` 抛异常 → 显式
      UTF-8,且**任何** error 一律 ERR(旧口径只认两种形状,其余被计成"未检出");
      默认端口 8896 迁 18896(179 的保留段教训)。**我方唯一剩余 FN
      (`pos-xs-01`)定性为打分口径**:XS-Leaks 审计层按设计给 low/firm,而"检出"
      定义为 high/medium/critical XSS 级 finding —— 不改成判定去凑数字。
      ③ **CSP 投递通道判定(先测浏览器再改判定)**:判定链只读响应头,而
      Chromium 对 `<meta http-equiv="Content-Security-Policy">` 一视同仁。
      五形态 × 真浏览器实测(`dev/_p196_csp_delivery/`):两种 enforcing 都沉默,
      两种 report-only 都不阻断 → 漏看 meta 是**过报**(FP)不是漏报。
      `csp.policies(headers, html)` 统一两通道并区分强制模式,
      `csp.blocks_family()` 读**全部** enforcing 策略(多条并立时任一条阻断即阻断);
      `verifier` 的 inline/attr/js-uri 三门 + sandbox 升级门 + `scanner_layers` L7
      同改(L7 不再把 report-only 当"可绕过的保护",同时第一次看见 meta-only 页面)。
      测试 `tests/test_phase196_csp_delivery.py` 20 例含 4 例真 Chromium 对照。
      **双引擎已对称**:`_scan_csp_async` 增加 `html` 形参、调用点
      (`async_scanner.py`)传页面 body,两条引擎经同一 `csp.policies()` 解析;
      同构断言按 (header, meta) 六种组合逐对比较 finding 数与 `csp_header`,
      防止再退化成"async 只读头"(本仓为此付过三次账)。
      ④ **API 前端门对齐(dalfox #1356 的我方版本)**:Phase 70 的同源门只写在
      `StdlibServer`,`--use-flask` 在未配 `--api-key` 时**一道都不执行**
      (重组页面可 GET 读走结果、跨站表单可起扫描),且测试套件里没有一条走 Flask。
      抽成共享纯函数 `same_origin_ok()` 两条前端各自调用 + 新增
      `Sec-Fetch-Site: cross-site` 拒绝(重组下 Host/Origin 都显示同源,只有浏览器
      这句不是);OPTIONS 走例外(stdlib 的 `do_OPTIONS` 从不过这道门,拦预检只会
      让 `--cors-origins` 放行的源到不了真实请求 —— 这条回归是我落地后实测发现的)。
      测试 `tests/test_phase196_api_gate.py` 12 例:共享函数五态 + 两条前端逐用例
      同构 + 反向对照(非浏览器客户端不受影响)。
      ⑤ **DOM 汇聚点面:测量先行,不照抄竞品 changelog**。dalfox v3.2.0 宣称
      新增 FileReader/setAttributeNS/parseHTMLUnsafe/拖放/剪贴板/间接 eval;真
      Chromium 实测后可归因源下:`setAttributeNS(null,'onclick',attacker)` 执行、
      `var f=eval;f(x)` 与 `window['eval'](x)` 执行、`setTimeout/new Function`
      执行;而 **`parseHTMLUnsafe` + append 不执行**,`dataTransfer`/`clipboard`
      源不可归因 —— 所以"跟清单"会加进一条浏览器否认的主张,同时漏掉我们真的
      看不见的那条(DOM 通道只 hook `setAttribute`)。补 `setAttributeNS` hook,
      `tests/test_phase197_dom_sinks.py` 双层(纯断言 + 活体端到端)并做**变异
      对照**(摘掉 hook 重跑活体路径,命中变空)证明守卫吃劲。
      ⑥ **靶场自己制造 ERROR(尺子缺陷,不是检测缺陷)**:`neg-header-01` mode
      `header_only` 把 query 值写进响应头,而全角变形族把整条载荷推到 U+00FF 之上;
      RFC 7230 下 stdlib `send_header` strict latin-1 直接抛异常 → 连接无响应关闭 →
      async 把 90s 全花在没拿到答案的用例上,严格门 ERR1。修在靶场:
      `_safe_header_value()` 让 ≤U+00FF 逐字节原样通过(既有期望零变动)、
      >U+00FF 百分比转义。守卫 `tests/test_benchmark_fixture_header.py` 5 例
      **含变异对照**:把 helper 打回恒等,同一请求必须仍然炸连接 —— 否则这条测试
      就只是"修好之后当然过"的空断言(本仓已被空守卫咬过多次)。
      门禁(本机空机复跑,非引用他人数字):strict 切片双引擎
      **FP0/FN0/ERROR0 f1=1.000** —— sync TP36/FP0/TN28/FN0/ERR0,
      async TP36/FP0/TN27/FN0/ERR0(1 SKIP = `neg-stored-02`,stored-dom 属
      sync-only);**补 `setAttributeNS` hook 之后再次复跑,数字逐项不变**
      (`benchmark/results/phase197_quick_{sync,async}.json`)——新 hook 若会自命中
      (Phase 193 那类:探针自身代码被当成页面命中),这一步就是它该被抓出来的地方;
      产物 `benchmark/results/phase196d_quick_{sync,async}.json`(修靶场后首验);
      修前同一切片 async 为 ERR1(`neg-header-01` 超时)—— 这条差值就是靶场
      造成的,归因走实测不是猜。range4 门禁 exit 0(首跑 async 两条 180s 超时
      核实为另一项目并发负载,空机重跑全对 —— 同形问题 187 就发生过);
      红队常驻 15 例 + CSP/verifier/API/MCP 定点批全绿;改动文件 ruff 零基线。
      **本轮新记缺口(`docs/OPTIMIZATION.md` 3.7)**:DOM 汇聚点面
      (`FileReader` / `setAttributeNS` / `parseHTMLUnsafe` / `dataTransfer` /
      `clipboard.writeText` / 间接 `eval`)全仓零命中 —— dalfox v3.2.0 加的正是这批,
      但动判定面必须先用 Chromium oracle 造可控/不可控对照,不为对齐清单直接加 sink;
      另:`werkzeug` 已移除 `__version__` 而 Flask 2.2.5 的 `test_client()` 要读它
      (测试改用 `werkzeug.test.Client` 驱动同一 WSGI app),依赖治理需钉住组合。

## 环境配置

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(2026-10-05 实测
  162 个 test_*.py 文件 / 38086 行,`pytest --collect-only -q` 收集 2622 用例;裸跑单进程会卡死,必须分批 —— `test_async_budget.py` 在本机
  会挂满 2×540s 预算,按"未验证"记账而不是当回归)
- benchmark: benchmark/ 目录;报告产物: report.html
- 三方对照(dalfox / nuclei)本机可跑:`go install github.com/hahwul/dalfox/v2@latest`
  经 goproxy.cn 构建到 `$GOPATH/bin`(本机为 `C:\GoWorkspace\bin`),nuclei v3.9.0 与
  `~/nuclei-templates/dast` 已在位;github.com 的 release 资产下载仍被拦(v3 Rust 版装不上)。
  跑法见 README"同类开源扫描器同靶跑分"一节;产物 `benchmark/results/phase196_cross_tool.json`

- [x] **198 双引擎行为对等门(OPTIMIZATION 2.1 落地,门当天抓到第一类新分歧)**:
      `tests/test_engine_parity_gate.py` —— 12 端点反射切片(manifest 既有
      用例,含 /s/flt05 与 /r/jsonct01 两个事故形状 + 两个 safe 孪生)双引擎
      同预算对跑,比较 **(type, severity, confidence) 有序多重集**。context
      排除是被实测论证的:同一参数多向量时"哪个 payload 先确认"是梯子顺序
      问题(/s/flt05: sync 确认 concat-stamp svg、async 确认 javascript:-URI,
      皆为真);count/severity/confidence 是 dedup/报告/PoC 重放实际消费的
      契约。**验收(2.1 硬要求)双向通过**:monkeypatch 摘掉 async 的
      content-type 降置信(178c)与 concat 重试(177),门各自变红。
      **门当天抓到第一类新分歧并修复**:async 的 L7 层 shim findings 视图
      缺主循环裁定(引擎不累积 finding,直接 yield)→ 共享 `_run_advanced_layers`
      的 polyglot fallback("仅当 (url,param) 无确认时")在 async 侧恒空转
      误发 —— 修为 shim seed(父 findings + param_confirmed 哨兵,yield 跳过
      seed);顺带修复两个引擎 polyglot finding 缺 `confidence` 键的报告元数据
      缺陷(消费者读 None)。回归 117 例 + benchmark async F1=1.0 + ruff 过。
      全量分批门禁 **161/163 文件绿(3035s)**:两个失败均为本条目自己的
      契约疏漏、门禁抓到即修 —— test_async_param_stage_parity 的替身缺
      `param_confirmed` kwarg(TypeError 被吞成"层未达")与 sentinel
      Finding 缺 `evidence_class`(evidence-coverage 门预算 0),复跑全绿。

- [x] **199 报告层性能基线(OPTIMIZATION 2.2,结论:不做)**:2.2 自己的
      方法论是"先建基准,没有基线就别谈优化了多少"。`benchmark/report_load.py`
      生成 N 条真实形状合成 finding(_record 字段全带,类型/上下文/严重度/
      证据级混合),八格式实测:**html 0.053s @1000 findings**(1.37MB),
      比 2s 验收线快 38 倍 —— 报告层不是瓶颈,f-string→join 重写不做。
      基准脚本 + 结果 JSON 入库可复跑;报告层再演进时先重测。
      测试 test_report_load.py 2 例(全格式跑通 + 合成 finding 确定性/字段
      完整);report 套件 67 例回归绿。**未跑全量门禁:零生产代码改动**
      (新增基准脚本 + 测试 + 文档)。

- [x] **200 async 测试密闭性守卫(OPTIMIZATION 3.8 结案,诊断被实测推翻)**:
      3.8 把 ~55s/_probe_param 记为"每响应判定 CPU"。复现后逐层排除:
      全部热点函数合计 0.11s/210 次、成本不随预算变化、faulthandler 线程栈
      显示执行器线程全程卡在 `getaddrinfo`、钩 `requests` send 计数确认
      **6 次真实请求 = L7 层(mutation/clobber/template/polyglot)载荷探针**
      经 `_get_sync_requester()` 的真实 Requester 发往测试假主机,本机劣化
      DNS 上每次 7-11s。修为密闭性守卫:`scan()` 建真实 aiohttp 会话时置
      `_sync_layers_online`,`_get_sync_requester()` 无旗标即拒绝(层的
      try/except 如实降级"层不可用")。效果:14/12 预算 _probe_param
      **62.7s→0.44s**(142 倍),HPP body 测试 55s+→0.66s。回归
      `tests/test_phase200_hermeticity.py` 3 例;async 套件 56 例绿;
      遗留记账:sync 层 Requester 不过 async throttle/egress jar。

- [x] **202 MCP 侦察工具 + 3.6 unsafe-hashes 关闭**:
      ① `api/mcp_server.py` 增两工具,面向 Agent 的侦察链(discover →
      profile → scan):**`xssentinel_discover`**(196 的 harvest 包装:渲染
      一次,回 SPA 表单字段名 + 同源 API 端点;playwright 缺失显式报错)+
      **`xssentinel_profile`**(kxss 式单请求 triage:sandwich 探针 + 共享
      context/反射画像 machinery,回 context/extra_contexts/meta_chars
      (raw=/stripped=/encoded=)/full_reflection/rcdata_tag,纯元数据零判定
      语义)。tools/list 三工具;MCP 套件 13 例全绿。② OPTIMIZATION 3.6
      item 2(unsafe-hashes 走到"利用")评估后关闭:hash 授权要求内容精确
      匹配,反射注入需 preimage(不可行);base-uri 劫持改内容即失配;
      挪用页面自带脚本需先有另一漏洞 —— 反射面上无可行路径,检出+修复建议
      即终点,不写投机逻辑。

- [x] **200 `--self-test` 首次跑完 + 归因出两个被 wedge 掩盖的真缺陷**:
      `--self-test` 自 Phase 182 起反复撞 900s 超时(Phase 187/192 记为
      "未验证"),本轮先修掉了 wedge 的**两个**成因:① self-test 靶场
      `tests/vuln_server.py` 用单线程 `HTTPServer` + HTTP/1.1 keep-alive
      → 一条空闲连接就饿死其余全部客户端(实测 netstat: LISTENING 与
      ESTABLISHED 并存,新客户端全部超时);改 `ThreadingHTTPServer` +
      handler `timeout=10`,并用一把只包住**请求处理**的 `_SIDE_CHANNEL_LOCK`
      保住 `/header-reflect`、`/graphql` raw_body、cookie_theme 的
      单线程语义(不包 keep-alive 空闲读,故不会饿死自己)。② 产品级
      **provisional navigation 陷阱**(与靶场无关,影响真实用户):
      `page.goto(wait_until="commit")` 抛超时后 Chromium 保持导航为
      provisional,下一个 `page.evaluate` 会一直阻塞到浏览器放弃 ——
      **实测 763.16s**(dev/_silent_nav_probe.py 三分支对照:失败 goto 2.02s
      → evaluate 763s;`goto("about:blank")` 恢复 0.02s → evaluate 0.0s);
      现场对应 `scan_endpoint('/evt')` 里 436s 的停顿,而 faulthandler
      只能看到 asyncio/greenlet 帧、报不出方法名。修复 `dom_engine`
      新增 `_recover_nav()`(失败 goto 后 about:blank,5s 上限,best-effort),
      `_bounded_goto` 与 `harvest()` 各接一处;测试
      `tests/test_nav_recovery.py` 9 例(含真 Chromium 静默服务器 <60s 界
      + 两个变异对照)、`test_vuln_server_concurrency.py` 6 例、
      `test_server_threading_audit.py` 3 例(repo 级规则审计,防旧形状复活)。
      **self-test 由此第一次跑完:790s、exit 1、5 项 FAIL** —— 而此前所有
      失败尝试都死在 wedge 上,所以这 5 项**没有任何历史基线**,
      必须实测归因,不能猜("判定不确定时必须返回 UNKNOWN 交回浏览器")。
      差分法:把本轮改动 `git stash` 后在**旧代码**上跑同一归因探针,
      同一探针同一靶场只换代码版本。
      归因结论(三项既缺陷 + 两项尺子/靶场缺陷):
      ① **`spa_crawler.crawl` 静默吞异常且从不回退**(最重):任何一次
      先前扫描启动了共享 sync 浏览器(`dom_engine.get_shared_browser`
      → `sync_playwright().start()`),该线程就**永久**留一个 running
      loop,之后每次 `SpaCrawler.crawl` 立刻死于
      "It looks like you are using Playwright Sync API inside the asyncio
      loop." —— 而 `spa_crawler.py` 的 `except Exception: return endpoints`
      只返回(通常为空的)部分结果,**不查 fallback**,于是爬取能力**无声
      消失**:调用方无法区分"这个 SPA 没有路由"和"浏览器起不来"。
      实测四点序列(**旧代码逐项相同**,故为长期既有缺陷而非本轮回归,
      被 900s wedge 掩盖了 18 个 Phase):全新进程 loop=False→10 端点;
      一次 DOM 扫描后 loop=True→**0 端点**;`shutdown_thread_browser()`
      后 loop=False→10 端点。对扫描的影响:爬取目标退化成单端点扫描
      (**40 请求 / 0.1s / 0 条发现**,而浏览器可用时是 **427 请求 /
      16 findings**),self-test 的"L7 爬到 /dom"与"L7 爬到 /echo|/script
      反射"两项即由此失败。修复:abort 时回退到调用方的静态 BS4 爬虫
      (新增 `_merge_endpoints` 并集助手,浏览器已登记的端点不丢);
      实测 wedged 态 **0 → 9 端点**、`dedupe 1→1` 变 `10→10`、
      scan_target 回到 **427 请求 / 16 findings / 1.48s**。
      测试 `tests/test_spa_crawler_fallback.py` 13 例,含一个**对照**
      ——同款输入下 pre-fix 形状返回空、修复形状返回端点,证明守卫吃劲
      而非空断言。
      ② **`_FONT_FACE_BLOCK_RE` 用 `[^}]*` 截断块体**(真 FN):模板插值
      天然产生 `}`(`url({{ asset }})`、`.../{{ font }}.woff2`),块体在
      第一个 `}` 处被截断,`unicode-range` 落到块外 → gadget 漏报。
      不对称可测:同构的 `@import` 模板形态**会**报
      `css_import_injection`,`@font-face` 形态**只**报 template 而丢 exfil。
      改为容一层嵌套花括号(有界,缺右括号不会吞掉整张样式表);
      `tests/test_css_injection_template.py` 15 例含缺右括号有界性、
      双 `@font-face` 仍各自匹配。
      ③ **CSSI 层只传参数名当证据**:`_scan_css_injection` 传
      `extra_markers=list(params.keys())`,而真正落进样式表的是**参数值**,
      于是反射型命中根本开不了门(只剩模板占位符一条路)。改为名+值都传;
      名字仍传是有理由的(样式表可能只引用变量名而不回显其值)。
      **Phase 140 的门本身完全正确,一个字没动** —— 它的存在依据是
      OWASP Juice Shop 实测(当时唯一的 finding 就是假的
      `css_font_face_exfil`,而两个真 XSS 全漏),所以修的是"喂给门的
      证据"和"块体正则",不是门。靶场同步补两条干净孪生
      `/cssi-font-face-safe`、`/cssi-import-safe`(此前只有正例,这条层
      只能证明"会报",证不了"不乱报");实测正例 fire、孪生沉默。
      ④ 靶场陈旧 `_sanitizer_strong_page` 仍钉 `dompurify@3.0.5`,而
      Phase 189 语料(`<= 3.4.15` 及 `< 3.1.3` 两条线,取自厂商
      advisory)判定其易受攻击 —— **发现为真,是靶场时基陈旧**,与
      Phase 189 修 `neg-sanitizer-01` 同族(那两处已升 3.4.16,此处漏升)。
      升 3.4.16 并补 `integrity`+`crossorigin`(Phase 189 记过:摘掉
      integrity 会撞 sri_bypass high,把一个 FP 换成另一个 FP)。
      ⑤ 另两页 CSSI fixture 自 Phase 140 起就不再表达"用户可控 CSS"
      (`q` 无占位符也不被反射进样式表),预期本身陈旧,随 ②③ 一并修。
      本轮自省要点:**"从未跑完过的门禁"等于没有门禁** —— 790s 首次
      跑完立刻暴露两个 18 个 Phase 未见的真缺陷,而其中最重的那个
      (爬取静默失效)在结构上**根本不可能**被任何单端点测试发现,
      因为它只在"先扫过一个用浏览器的端点、再爬取"这个顺序下现形。
      **门禁终态(本机实测,非引用)**:全量分批 **168/169 文件绿(4535s)**,
      唯一失败 `test_phase196_csp_delivery.py` 两次 attempt 均 TIMEOUT、
      门禁后单文件复跑 **21 passed in 9.66s** → 同机另一项目并发 pytest
      抢占 loopback 的资源争用形态,**与本轮改动零交集**(该文件测 Phase 196b
      的 CSP 投递通道),按环境形态记账。`--self-test` **ALL CHECKS PASSED**
      (Phase 182 以来首次);strict 64 例切片双引擎 FP0/FN0/ERROR0 exit 0
      (`phase200_quick_{sync,async}.json`);range4 双引擎 TP2/FP0/TN2/FN0/ERR0
      exit 0(`results_verify_phase200.json`);benchmark 既有三条 CSSI 用例
      定点复跑 TP/TN/TN(`dev/_cssi_bench_cases.py`,因 64 例切片只含其中
      一条负例,阳性 `pos-cssi-01` 不在切片内 —— **切片绿灯不等于这层没变**)。
      另 `--self-test` 自身也修了尺子:CSSI 两个端点原本以 `params={}` 扫描,
      而门要求"用户可控"的 CSS 才有资格触发 —— 门是对的、**测试是陈旧的**,
      改为带 `q=xssent` 扫,并补两条反向断言(干净孪生必须沉默),
      否则"删掉门"会看起来像通过。
      **两个本轮记下但已测清的开放问题**:① `about:blank` 恢复是否破坏
      `window_name` 探针 —— 实测**不影响**(两臂对照均存活;Chromium 规范上
      恢复后探针会重新设置 `window.name`,恢复只发生在**失败 goto 之后**,
      而 window_name 探针自己的 goto 不失败);② Juice Shop 外部效度实测
      (v20.2.0 官方包,MD5 与官方 `.md5` 逐字节匹配,ground truth 取自
      上游 `challenges.yml` 而非本仓:**9 XSS / 69 非 XSS / 38 其他**)
      —— **结论是"还不能测",不是"测过了"**:9 条 XSS 里 7 条需登录态 +
      持久化写入、2 条是纯 DOM 层、**0 条是未认证 query 反射型**,与无头
      CLI 扫描的覆盖边界交集接近空,故 53 请求 0 findings 是**预期而非漏报**。
      记录见 `dev/_JUCESHOP_EXTERNAL_VALIDITY.md`;按 190 的纪律不进
      README、不进门禁 —— 外部效度需要一个"登录→持久化注入→跨会话回访"
      的驱动器(range3 已有该三段流程,是独立的一个 Phase)。
      **本轮自己也踩了三次尺子错,都记在案**:① 用 `-match` 判"反射",
      命中的是数据库里真实产品名"Apple Juice" —— **看似反射 ≠ 反射**;
      ② 从 `dev/` 跑脚本时本机另一份 editable 安装(`D:\op\xssentinel`)
      **静默劫持导入**,探针会量到另一棵树,症状是"仓库里明明有这个符号
      却 ImportError" —— 已加 `dev/_pin_repo.py` 强制校验解析结果;
      ③ 外部效度的尺子本身尚未建好,差点把"测不了"写成"通过"。
- [x] **201 同族 wedge 的收尾(一处真修复 + 一处否证 + 一处方法论教训)**:
      200 的回退修的是"爬取整体中止",留下一个更窄的洞。顺着同一模式查下去:
      ① **否证 —— `verifier.verify_headless` 没有这个 wedge**
      (`dev/_VERIFY_HEADLESS_WEDGE.md`)。它是"candidate → 浏览器确认证据"
      的主路径,若同病则受害的是最关键的确认环节,所以值得先查。
      实测两臂打同一台静默服务器:arm A 失败 goto 后,下一次调用
      (`wait_for_load_state`)**5.02s 后按约定抛 TimeoutError**;arm B
      `about:blank` 恢复 0.02s、其后调用 0.00s。**关键差异不是 try/except,
      而是每次浏览器调用都带 timeout** —— dom_engine 那个 763s 是
      `page.evaluate` 挂到浏览器放弃,这里有界。**结论:不改。**
      按纪律"没量过的改动不进代码,量过是不需要的更不该进"记档 ——
      同族问题最容易被顺手一起修掉。
      ② **真缺陷 —— `spa_crawler` 的 goto 失败分支把页面留在 provisional 态**
      (`dev/_dom_links_wedge_probe.py`):`crawl()` 里 `page.goto` 抛异常时
      只 `continue`,**不恢复页面**,于是该页此后每次 `page.evaluate`
      阻塞。实测 `_extract_dom_links` **117.02s** 后返回 `[]` —— 比 200 修的
      顶层中止更隐蔽:爬取继续跑,只是把"这个 SPA 没有链接/路由/表单"
      当结论报出来,四类采集(DOM 链接、SPA 路由、表单、XHR)全部静默归零。
      修复放在 **goto 失败分支**(而非四个 evaluate 站点):接
      `dom_engine._recover_nav`,复用已验证的 about:blank 形状。
      **修法位置是被实测纠正的,不是设计出来的**:先在
      `_extract_dom_links` 里加恢复,复测仍是 **117.02s、一秒没省** ——
      因为 handler 只在 evaluate **抛异常之后**才触发,而它在那 117 秒里
      根本没返回。**"在异常处理器里修一个"先阻塞 117 秒再抛异常的问题"
      是无效修法**。端到端复测(crawl 入口):**117.02s → 3.69s**,
      0 端点仍是**正确结果**(页面确实不存在),变的只是耗时与沉默。
      测试 `tests/test_spa_crawler_nav_recovery.py` 4 例:恢复先于 evaluate /
      恢复用 about:blank / **健康页绝不多做一次导航**(防"无条件恢复"把
      SPA 路由 init script 的状态每次访问后都毁掉)/ 变异对照。
      ③ **有据的不对称,不是漏修**:`async_scanner_crawl.py` 全文件零
      `goto`/`evaluate` —— async 爬取是 aiohttp + JS 静态挖掘,不经浏览器,
      这个 wedge 在 async 引擎上**结构上不存在**,故无对位块可写。
      **门禁(本机实测)**:strict 64 例切片 **双引擎** FP0/FN0/ERROR0 exit 0
      (sync 64 例 0 SKIP / async 63 例 1 SKIP = stored-dom 属 sync-only,与 200 同;
      `phase201_quick_{sync,async}.json`);range4 双引擎 TP2/FP0/TN2/FN0/ERR0 exit 0。
      range4 sync 首跑曾 `r4-pos-react-dsi` 180s timeout,但**单文件复跑
      15.9s TP / 12 findings / browser-confirmed=12** —— 与 187/200 记过的
      同机并发争用形态一致(当时 strict 切片正在同机跑),按环境形态记账。
      受影响面 63 例全绿(spa_crawler 4 文件 + dom 导航 2 文件),改动文件 ruff 零债。
      **续测(同日)**:受影响面扩到 **68 例 2.27s** 全绿;crawl/layer/coverage/
      parity/engine/dom_engine/spa **21 文件族**在跑时被同机另一项目的批处理门禁
      拖死(栈卡 `socket.socketpair()` 的 `accept()`,905s 超时)。
      `--self-test` **ALL CHECKS PASSED、exit 0、778s**(200 之后第二次连续通过)。
      **全量分批门禁本轮三次撞同一形态,按"未验证"记账**:187(range4 180s 超时)、
      200(`test_phase196_csp_delivery.py` 双 TIMEOUT、单文件复跑 9.66s 通过)、
      201(**687 分钟只落盘 2 个文件**,同期 `D:\qoder\vuln-agent` 的
      `run_tests_batched.py` 连续跑了 604 分钟且仍在 fork pytest,双方同一秒
      各起一个 pytest)。差三个数量级即是证据:清理后同一受影响面 **2.27s**。
      **用户已两次拍板**:先"等对方跑完"、对方换了一轮又起(15:28 新 PID 3608)
      后改为"不等了,按未验证收口"。故 Phase 201 **不声称全量门禁通过** ——
      下一轮环境干净时必须补跑,且跑前先执行下面的进程表检查。
      完整归因、进程表读数与**给下一轮的可执行前置检查**记于
      `dev/_WEDGE_gate_20261006.md` —— 三次的形态完全一致
      (同机并发 → loopback/Chromium 争用 → 超时或停滞,而单文件复跑一律全绿),
      故本轮**不拿受污染的数字做结论**。
      读日志的坑也记一笔:`test_async_budget.py` 常态触发重试
      (`attempt 0 rc=TIMEOUT` / `attempt 1 rc=0`,`11 passed in 528.98s`),
      **只看 "11 passed" 会低估整轮真实耗时**,必须读 `attempt 0`。
      **门禁脚本的副作用也踩了一次**:`range4/runner.py` 分臂跑会把入库的
      `range4/results.json` 覆写成**单臂 4 行**(原为双引擎 8 行,
      `git status` 显示 332 deletions),已 `git checkout --` 恢复、单臂结果
      另存 `results_verify_phase201_async.json`。**要么用 `--out` 指定新文件,
      要么跑完检查 `git diff range4/`** —— 门禁顺手覆盖版本控制里的历史产物,
      下一个人会以为双引擎结果变了。
      **本轮的方法论教训**:"同族问题"值得查(本轮就查出一个真的),
      但**每一条都必须各自测量** —— 同一个假设下,一条真缺陷、一条否证、
      一条结构上不存在。三条都记在案,免得下轮把否证的那条顺手"修"了。
      **工具入库(用户拍板)**:`dev/_pin_repo.py` → **`dev/pin_repo.py`
      去前缀入库**(仿 `dev/fetch_range5_vendor.py` 的先例 ——
      **可复跑的取证属版本控制**)。它强制 sys.path 指向本仓,并在解析到
      别的树时抛错:本机那份 `D:/op/xssentinel` editable 安装会**静默劫持**
      从 `dev/` 跑的探针,症状是"仓库里明明有这个符号却 ImportError",
      极易误读成被测代码坏了。改名后实跑依赖它的探针验证可用:
      `_verify_headless_wedge_probe.py` exit 0 且**否证结论复现**
      (arm A 5.02s 有界 / recovery 0.00s / wedge=False)。
      **顺手修了改名时自己造成的一个事故**:`Set-Content -Encoding UTF8`
      给三个探针加了 **BOM**,AST 解析直接 SyntaxError(U+FEFF)——
      **改文件后必须 AST 复验,不能只看 ruff**(ruff 当时报的全是别的);
      同批还清掉 `_verify_headless_wedge_probe.py` 里被否证假设遗留的未用
      局部变量(`recovered`,探针算出一个谁也不读的裁决,正是假设悄悄变成
      结论的路径)与 `_window_name_recovery_probe.py` 的两个真冗余导入。
      **续:又一次否证 + 一条新守卫**。修复加的那行
      `from .dom_engine import _recover_nav` 在 `except` 块内、**自身无 guard**,
      而 `_recover_nav` 的 docstring 承诺"recovery must never turn one
      failure into a crash" —— 那承诺覆盖它自己的函数体,**不覆盖抵达它的导入**。
      看起来是我自己引入的新失败面。**实测:不是**(`dev/_recover_import_probe.py`,
      记于 `dev/_RECOVER_IMPORT.md`):三臂打同一个抛 goto 的假页面 ——
      A 真导入 `ok` 且页面收到 `[app, about:blank]`;**B 让导入抛 ImportError
      仍 `ok`**(外层 `except Exception` 兜住);**C 让 `_recover_nav` 抛也 `ok`**;
      `import_failure_escapes_crawl=False recover_nav_contract_broken=False`。
      **结论:不加 guard**,三条理由都基于读数:① 不可达(实测外层已兜住);
      ② 再套一层 try 是"看起来更安全"的假象、零可测量收益(与 ① 同一条纪律);
      ③ 真发生时后果是**退化不是崩溃** —— 退回静态爬虫正是 200 建立的
      已测量降级路径。否证顺带产出**三条新守卫**:recovery 抛异常不逃出 crawl /
      导入失败降级到 fallback / **`BaseException` 不被吞**
      (Ctrl-C 必须真能停扫描 —— 把"recovery 绝不崩溃"钉住它的边界,
      免得下一个人把这条边界当成疏漏去"修")。写第二条时测试当场抓到我自己
      漏了 `import pytest`。
      **续二:替身保真度也是量出来的**(`dev/_double_fidelity_probe.py`)。
      拿 `_WedgedPage` 与真实 Playwright 的 surface 对比,抓到**三处不忠实**:
      ① `page.url` 缺失;② `wait_for_load_state(**kwargs)` 放行了真实签名会拒的
      调用;③ **`page.new_page` 是凭空发明的**(真实 Page 没这个方法)。第 ③ 条
      最危险 —— **替身能响应真实代码不可能发出的调用**;而缺失属性会抛
      AttributeError **被它本该检验的那些 `except Exception` 吃掉**,于是测试
      看着绿、实际什么都没量。修完(拆 `_FakeContext`、
      `wait_for_load_state` 改 keyword-only、补 `url`)复测 `faithful=True`。
      顺带修了 `_WedgedPage` 类 docstring **说谎**(写"evaluate 会阻塞",
      实现是 raise)—— 本项目反复记录的"文档刻度失真"形态。
      **续三:变异对照差点造成一条假记录**(`dev/_MUTATION_CONTROL_LESSON.md`)。
      首次变异用正则替换 recovery 调用,结果 **7 passed**,看着像"守卫是空的";
      **但那是假的 —— 正则没匹配上真实缩进,所谓"变异后运行"跑的是原始代码**。
      若就此下结论,会写出两条都错的记录(误判守卫无效→删掉有用的断言;
      或反过来因为"仍绿"去加强本来没问题的断言)。改成严格脚本
      `dev/_recovery_mutation_control.py`:**先断言文本存在再变异**
      (找不到就 `MUTATION ABORTED` 退出码 2,绝不"跑一遍看看")+ **跑三遍**
      (baseline/mutated/restored 都在转录里)+ **只有 mutated 红且 restored 绿
      才算通过**。实测 `baseline rc=0 / mutated rc=1(3 failed)/ restored rc=0`
      → `guard_is_load_bearing=True`。
      **一句话教训:变异对照的输出和被测代码一样需要被怀疑 —— "跑完了"不等于
      "变异生效了",判据是有证据证明源码确实变了。**
      **续四:守卫自己也要被变异检验,而且它咬出了三个 100% 空转的断言**
      (`dev/_double_fidelity_mutation.py`)。给替身保真加的 2 条新守卫,一做
      变异就塌了:① `assert "kwargs" not in sig.parameters` 读起来正是"不能是
      catch-all",**实际完全空转** —— `inspect` 只在参数是 keyword-only 时把它
      命名为 `kwargs`,裸 `**kw` 显示为 `kw`;② 用 `Page ∪ Browser ∪
      BrowserContext` 的**名字并集**比对,而 `new_page` 真实 `Page` 上没有、
      `BrowserContext` 上有 → **并集正好放行了 `_WedgedPage.new_page`**,
      恰是它要抓的凭空发明;③ 守卫只查"多出来的成员",**纯删除方向完全不设防**
      —— 删掉 `url` 仍 9 passed。
      修法都是回到"比较的是什么":判据从**参数名**改成**参数 kind**;
      比对从**并集**改成**按角色**(Page 替身只比 Page,Context 替身只比
      BrowserContext);补 11 条 `REQUIRED_PAGE_MEMBERS` 参数化断言堵删除方向。
      最终四个变异(重加 `new_page` / goto 退化 / wfls 退化 / 删 `url`)
      **全部变红** → `double_guards_are_load_bearing=True`。
      顺带修掉变异脚本自身的真问题:`finally: shutil.move(BAK, TARGET)` 在
      Windows 失败过一次,**把测试文件留在变异态**,`restored` 一直红,差点被读成
      "守卫有问题" —— 改成字节写回 + 还原后逐字节自校验,不一致即退 2。
      **三条可复用判据**:① 判据要测被测物本身,不是它的某个表示;② 比对要按
      角色不要按并集(并集把"A 没有 B 有"变成两边都合法);③ 守卫只覆盖一个
      漂移方向时必须明写另一方向无人看守。
      **续五:参数化守卫自己也会被装饰**(`dev/_required_members_probe.py`)。
      上面那条 11 名的 `REQUIRED_PAGE_MEMBERS`,探针读生产 AST 一查,**有 4 个
      (`content`/`context`/`is_closed`/`url`)在整个 `xssentinel/` 里零引用** ——
      我是凭"Page 应该有"加进去的。它们是**装饰**:只有有人改列表才可能失败的
      用例,只会虚增例数、什么都不保护。删到 7 个(每个带 `spa_crawler.py` 的
      行号注释),7/7 全部 `USED`,`every_listed_member_is_load_bearing=True`;
      并把"列表成员必须被生产代码引用"这条**内联进测试**(读 AST 而非靠人记得
      跑 dev 脚本)。**参数化守卫的特有失效模式:名字来自信念而非推导。**
      **续六:守卫集合本身也可被增删而无告警。** 变异"从
      `REQUIRED_PAGE_MEMBERS` 删掉 `goto`"→ **16 passed,全绿**:列表 7→6、
      参数化用例 7→6,**没有任何东西察觉**,因为没有断言看着集合本身。
      补双向断言(`expected - LIST` 与 `LIST - expected` 都必须为空),与已有的
      "必须被生产代码引用"合成三向闭合:**不许多、不许少、不许是信念**。
      **五种失效形状**:① 测了表示没测被测物(查参数名);② 测了错误的对照集
      (并集);③ 测了一半方向(只查增加);④ 测了列表没测被测物(凭信念列名单);
      ⑤ 集合本身可被增删而无告警。**参数化守卫的验证对象是集合的每个成员
      和集合本身,不只是断言。**
      **续七:端到端数字当场重测,不引用。** 单元守卫全是替身,只证明 recovery
      被调用,不证明它有效果 → 重跑端到端(`dev/_spa_wedge_recheck.py`,
      真实浏览器 + 接受连接后永不回字节的服务器):**elapsed 3.67s**,
      `crawl_under_90s=True fixed_present=True`,与当初记录的 3.69s 一致。
      **"117s → 3.7s"是一句关于某一次跑完的运行的断言;fixture 或修复一旦漂移,
      它会静默变成假话,而所有单元测试照样全绿 —— 本轮没复现过的引用数字不是
      证据。** 顺带:该探针第一次 `from core.spa_crawler import` 报
      ModuleNotFoundError —— 与"导入了 D:\op\xssentinel 那棵树"同类,
      **路径决定你量的是哪棵树**。
      **续八:第一次找到指向产品数据面的真实缺口**
      (`dev/_CORPUS_DERIVED_GUARDS.md`)。顺着"参数化守卫的成员应从被测对象
      派生"横扫 tests/,找到 25 处字面量 parametrize 列表 —— **但 25 不是
      结论**:抽查后大多数是正确的(列的正是契约本身),凭计数去改会把对的改成
      错的。逐个抽查找到**一处真实的单向断言**:
      `test_p27.py::test_compliance_mapping_exists` 的 docstring 写着
      "Each new finding type must map to at least one compliance entry",
      却只能检查它自己列的 9 个类型,而权威集合在
      `data/compliance.json` 的 `finding_type_map`(**没有任何东西对比两者**)。
      实测:语料 **129** 类型 / 测试列 **9** / **114 零覆盖**(扣除 prefix
      fallback);`stale=0` 但**无机制保证它干净**。同型的
      `test_finding_type_has_compliance_mapping` 只查 `len(entries) > 0`,
      **不查条目形状** —— 缺 `url`/`requirement_id` 的条目能通过却在报告里
      渲染成空行。
      修法:保留手写列表作重点快测,**另补从语料派生的两条**(有映射 + 条目
      四字段齐全)→ **246 例通过,0.81s**,语料全部合规且形状完整。
      **三条判据**:① docstring 声称的范围必须能被检查,否则那句话在说谎;
      ② 方向要对称(只查"列出的都在"就漏掉"该有的没列");③ **非空不等于正确**。
      **前七轮修的都是测试代码自身;这一轮第一次靠一条测试侧的规则找到了产品
      数据面的缺口 —— 边界不在文件里,在"谁在断言什么"上。**
