# XSSentinel — 综合型 XSS 检测框架

![CI](https://github.com/feixingxuerong123/xssentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

> 一款**多层级、可扩展**的 XSS 检测工具：反射点上下文感知注入 + WAF 自适应绕过 + DOM 污点分析 +（可选）无头浏览器真实验证。

中文 | [English](README.en.md)

---

## ⚠️ 定位与诚实声明（请先读）

市面上成熟的商业工具（如 Acunetix、Burp Suite Pro、Netsparker）由大型团队长期维护，覆盖大量私有规则与爬虫能力。**没有任何一款开源工具能"全面超过"它们**——这是个移动靶。

XSSentinel 的目标是**在开源/自研工具中做到检测维度最全、架构最干净、最易扩展**：它把通常被单点工具割裂的能力整合进一个流水线，并且每一层都可单独替换/增强。它在以下方面优于常见的单技术 XSS 脚本：

### 成熟度声明（2026-11-02 实测口径：**Beta**）

本项目的 `pyproject.toml` 分类自 2026-11-02 起为 `Development Status :: 4 - Beta`，
不再声称 `Production/Stable`。按当前可复现实测：

- **已具备**：反射/DOM/存储三类主路径的语义确认；第三方 XSSMaze v0.3.0 同靶
  **TP944 / FN69 / FP0（P 1.000 / R 0.932 / F1 0.965）**；27 条控制例本轮
  sync/async 复跑均 **0/27**；本仓库自编 194 例矩阵 sync/async 双引擎 FP0/FN0；
  存储自动发现官方靶 **sync 9/9、async 9/9**（2026-11-03 实测）；async stored
  洁净复测 **19.2s vs sync 15.9s（1.21×）**，在 ≤2× 目标内；真实应用 v2.2
  22 例 / 5 个 app（登录后反射、持久化反馈、API-only、Header 注入、自建四面靶、
  bWAPP）xssentinel **13 TP / 0 FP / 9 TN**，每例有官方 challenge/源码/
  bWAPP `bugs.txt` 或自建靶构造 + 独立 Playwright ground truth。
- **尚未具备（因此不是 Production/Stable）**：① 多角色只覆盖 admin + 一个低权限
  账号（DVWA `gordonb`、Juice customer/deluxe、bWAPP `bwuser`），未覆盖完整权限
  矩阵；低权限写入→高权限查看的 stored XSS 已验证；Juice deluxe 经官方
  `freeDeluxeChallenge` 路由（`POST /rest/deluxe-membership`）合法可达，
  accounting 在本版本不存在；
  ② **没有与商业工具（Burp Pro / Acunetix）的对跑**，本机无安装/授权；
  OWASP ZAP 已永久标注 `unavailable`（ghcr denied / Docker Hub 镜像 TLS /
  GitHub 超时 / PyPI 包仅 74KB 客户端），不暗示优于商业工具；③ Juice Shop 的
  持久化反馈在 Docker + unsafe 配置下由**服务端** `sanitize-html` 在入库时剥离
  （POST 响应即可见空值），18 个载体逐一测试 0 个可执行，不是前端渲染问题；
  该类别由 DVWA guestbook、bWAPP blog 与 Juice 商品描述覆盖；结论已定，
  不再投入实验；XVWA 不可达；
  ④ 40 例分层样本最终代码 A/B 实测
  **83.7s → 51.8s（1.62×）**，落在 40–53s 目标区间；剩余成本
  在进程启动与必须开浏览器的 DOM 正例，transform 阶梯已不是主成本（剪枝实验
  无收益，已回退）。
- **适用边界**：授权范围内的单目标/小批量 XSS 专项测试与 CI 回归可用；
  大规模生产资产测绘、需登录的多角色工作流、以及"零漏报"承诺不在当前能力内。
- 本轮（2026-11-03）完整验收数据（27 控制例、ruff、真实应用 v2、A/B、strict
  门禁、async stored 对齐）见 `benchmark/results/round2_report_20261103.md`；
  三个缺口补测（Juice 反馈归因、ZAP 可用性、多角色）见
  `benchmark/results/round3_gap_report_20261103.md`；async 归因、自建四面靶、
  DVWA 三档权限矩阵见 `benchmark/results/round4_gap_report_20261103.md`；
  bWAPP 接入、XVWA/ZAP 最终处置、Juice deluxe 合法路径见
  `benchmark/results/round5_bwapp_report_20261103.md`。

### DOM 静态分析层的能力边界（Phase 354，2026-11-03 实测）

DOM 静态层是 **AST 优先、正则兜底**：`esprima` 可用时先走 `js_ast` 的跨语句
污点链；解析失败（压缩/混淆/语法扩展）才回退到 `dom.py` 的正则窗口。正则是
**启发式**，它给出的是"值得人工复核的线索"，不是执行证明。本轮按真实页面
（Juice Shop、DVWA）与真实框架写法做了规则精度收敛：

| 形态 | 调整前 | 调整后 | 依据 |
|---|---|---|---|
| `document.title = location.hash`（SPA 标题路由） | medium（会报） | 不再命中 | title 只写文本，不解析 HTML |
| `setAttribute('aria-label', location.hash)` | medium（会报） | 不再命中 | 非可执行属性 |
| `$('#m').attr('title', location.hash)` / `.val(...)` | medium（会报） | 不再命中 | 非标记/非可执行属性 |
| `$('#m').attr('href', location.hash)` / `.prop('innerHTML', …)` | medium | medium（保留） | 可执行属性/属性 |
| `setAttribute('onclick', location.hash)` | medium | medium（保留） | 事件处理器 |
| `el.appendChild(location.hash)` | medium（会报） | low（抑制） | appendChild 本身不解析标记；真正 sink 是创建该元素的那一步 |
| `innerHTML = location.hash` / `document.write(location.hash)` | medium / high | 不变 | 真 sink |

证据（本次实测，不是沿用文档）：在 DVWA guestbook 页面（+登录、security=low）
上静态层产生 **120 条 low 线索、0 条 medium/high**，扫描器对 low 全部抑制，
因此该页在无浏览器模式下不会产生 DOM 告警；Juice Shop 首页/搜索页为 0 条。
同一轮把上述 5 类"真实框架写法"注入为 `<script>` 片段，收敛前 5/5 被判
medium、收敛后 0/5 进入报告，而 `innerHTML`/`document.write`/`attr('href')`/
`setAttribute('onclick')` 仍为 medium/high（回归见
`tests/test_dom_static_precision.py`）。

**仍然收敛不了的边界（明示，不假装解决）：**

- **计算属性名**：`el.setAttribute(nameVar, tainted)`、`el[nameVar] = tainted`
  这类属性名本身是变量的写法，正则与当前 AST sink 名单都无法判断是否危险；
  置信度按 low 处理，交给浏览器臂或人工。
- **跨语句对象身份**：`const d = new DOMParser()…; el.appendChild(d.body)`
  是否可执行取决于 `d` 的创建方式，正则跟不了对象身份——这正是 AST 层存在
  的原因，AST 解析失败时该形态可能漏报。
- **外部 bundle**：静态层只分析内联 `<script>`，不下载/解析外部 JS；SPA 的
  sink 通常在 bundle 里（例如 Juice Shop），这类只能靠 `--headless` 浏览
  器臂在真实 DOM 上观察执行。
- **置信度语义**：无 Playwright 时 medium = "源码级可疑，需人工确认"；
  只有浏览器臂的 `browser-executed` 才是"已执行"证据。low 一律不进入告警。


<details>
<summary><b>展开完整能力清单（含实现出处与标定历史）</b></summary>


- **6 层检测流水线**：反射 → WAF 绕过 → DOM 污点 → 存储型 → 盲打(OOB) → 无头确认，覆盖大多数工具只做其中 1–2 项的盲区。
- **上下文感知**：先判断输入反射在 HTML 元素 / 属性 / 脚本字符串 / 事件处理器 / `javascript:` URI / SVG / MathML / CDATA / 模板 `{{}}` / meta-refresh / HTML 注释等 **20+ 种上下文**，再选对应 payload。
- **反射画像驱动（Phase 31）**：反射确认后自动发一枚"三明治探针"（DalFox 式），识别哪些特殊字符被过滤/编码，按需把最可能命中的 payload 与 WAF 绕过变形排到队首（ZAP 式字符反馈闭环），预算利用率更高——benchmark 上同等精度下总耗时下降约 10%。
- **生成式 payload（Phase 32）**：不只检索语料，还按反射画像用**仅存活的字符**现场构造 payload（XSStrike 思路）；括号被过滤时自动切换为无括号的 tagged-template 调用 `alert\`1\``，能穿过拦住语料 payload 的过滤器。
- **签名级端点去重 + 内容类型降置信（Phase 32）**：爬虫产物按 `方法+主机+路径+参数名集合` 去重，分页/重复参数的端点不重复扫（DalFox 思路）；JSON/纯文本响应中的反射命中自动降为 low confidence（ZAP 思路），让人优先看真正的 HTML 汇聚点。
- **参数位置变换（Phase 33）**：WAF 常只守参数的原始位置——标准位置全部未确认且检测到 WAF 时，自动把 top payload 克隆到另一位置（query↔body）重发（Burp 思路），固定小预算不膨胀请求量。
- **审计优先级 + 策略预设（Phase 33）**：并发队列按攻击面价值排序（参数数 / POST / admin·comment 等敏感路径优先，Burp 思路）；`--scan-policy {quick,normal,deep}` 一键切换预算档位（ZAP Threshold/Strength 思路），显式 flag 始终覆盖预设。
- **自动预编码管道（Phase 34）**：自动识别 base64 / 双重 base64 / JSON-in-base64 / JWT 容器参数，把 payload 用**同样的容器重新包装**后注入（DalFox 思路）——JWT 保留 header 与签名段、JSON 追加字段；命中即跳过对结构化参数几乎无望的明文 payload 循环。
- **CSP 感知预算门控（Phase 35）**：strict CSP（内联被禁且分析器未发现绕过路径）时自动把反射 payload 预算切到早停档，nonce 策略保守放行（可能存在 nonce 泄露绕过）；可绕过的 CSP 保持全预算。`--async` 高吞吐模式同步接入预编码管道（Phase 43 修复：async 主入口的 `as_completed(async_generator)` 误用与 scan-policy 预设填充缺失均已修复，`--async` 单目标/批量现已端到端可用并有真实 HTTP 回归测试守护）。
- **验证器 RCDATA 加固（Phase 35）**：lxml 的 HTML 结构修复会把写在 `<title>/<textarea>/<xmp>` 内的标签提升到文档顶层、丢失 RCDATA 祖先——语义验证器现在在结构化解析**之前**先做原始文本 RCDATA 检查，杜绝该类罕见误报；真正的 `</title>` 后逃逸仍然照常确认。
- **WAF 自适应绕过**：检测到拦截后，自动套用 **28 个**变形/编码家族（混合大小写、HTML/JS/CSS/UTF-7 实体、注释打断、空字节、全角、构造器逃逸、重复属性等）生成绕过变体；数量以 `core/transform.py` 的 `REGISTRY` 为准，新增变形只改 REGISTRY 即可。
- **DOM XSS 静态污点分析**：不依赖服务器响应，直接分析前端 JS 的 source→sink 流（如 `location.hash` → `innerHTML`、jQuery `.html()`、`postMessage` 事件、`dangerouslySetInnerHTML`、`v-html`、`{{ }}` 等）。
- **JS AST 数据流分析（Phase 43）**：esprima ESTree 解析每个 `<script>` 块，跟踪污点变量跨声明/赋值/拼接的多跳传播（含压缩混淆代码与 postMessage 回调函数体），产出带 `[AST]` 标记的高置信 source→sink 链（DalFox v3 式）；解析失败透明回退正则通道（`pip install xssentinel[ast]` 启用，缺失时自动降级）。
- **DOM XSS 真·浏览器执行确认（L6 强化）**：在真实无头浏览器（Playwright）里给危险 sink 插桩——`innerHTML`/`outerHTML`/`document.write`/`Function`/`setTimeout`/`location.*`/`window.open`/`setAttribute(on*)`/jQuery `.html()` 等，并把唯一标记注入 `location.hash`/`location.search`/`document.cookie`/`postMessage` 等可控源。**只有页面自己在真实浏览器里执行了载体（弹窗携带本次探针的 token）才判定为已确认（high）`dom_dynamic`**；数据到达 sink 但没有观测到执行时，单独记为 `dom_sink_reachability`（low，投递线索，**不是已确认 XSS**，也不生成可执行 PoC）。这样净化器正确使用的页面（如当前版 DOMPurify + innerHTML）不会被报成高危；range6 的双引擎门禁同时验证 2.0.7 真执行 / 3.4.17 静默。Playwright 不可用时优雅降级为静态启发式，不影响其他层。
- **DOM 重建链（Phase 185）**：覆盖 `DOMParser.parseFromString` → `importNode` / `adoptNode` / `cloneNode` → `appendChild` / `insertBefore` / `replaceChild` / `append` / `prepend` / `after` / `before` / `replaceWith` 这条「解析后重建 DOM 再插入」的链路——真实世界绕过 DOMPurify 类净化的主流写法。判定走**污点传播 + 插入时复查节点当下是否仍含标记**：净化器若已把 onerror 摘掉，插入时就不会命中；插入纯文本节点也**不算**命中（`benchmark/sink_execution.py` 实测它根本不执行）。
- **存储型 XSS**：注入后重新拉取"展示页"确认持久化执行（多数开源工具不做）。
- **盲打 XSS（OOB）自动确认**：注入带唯一 token 的带外回调 payload，再轮询回调监听服务——**收到 beacon 即判定为已确认（high）盲打**，而非只"撒网不收网"。支持自托管监听器（`--oob self`，离线可测）与公共 interactsh（`--oob interactsh`，真实场景）。
- **双重确认**：语义确认（token 是否落在真实可执行汇聚点，且用 BeautifulSoup 结构化判定，可识别 `html.escape` 伪漏洞）+ 可选无头浏览器真实弹窗确认，显著降低误报。
- **深度爬虫**：`-c` 自动发现同域 `<a>` 链接与 `<form>` 端点（BFS，`--crawl-depth` 控深度，`--scope` 限域），连"无参数纯 DOM 页面"也纳入扫描——多数单脚本工具跑完一个 URL 就停了。
- **发现去重**：`dedup()` 按 `(type, URL, param, context)` 合并经不同爬取路径/变形变体发现的同一漏洞，避免重复告警刷屏（DOM 类忽略 query 差异）。
- **隐藏参数挖掘（Phase 43）**：内置 313 个高产出候选词（分页/token/回跳/模板等 14 类），`--param-wordlist` 可追加自定义词表（操作符提示前置）；fuzzer 差分 triage 从大词表挑 top-N 深测，请求量可控。
- **双引擎精度对齐（Phase 43）**：`benchmark/runner.py --engine {sync,async}` 用同一矩阵分别标定两条流水线（该矩阵现为 194 用例；Phase 43/69 标定时为 98 用例）——async 经 CSP 响应头门、转义实体窗口、mXSS payload 自带结构守卫三层修复后已达 **recall 100% / precision 100% / FPR 0**，与 sync 完全对齐（Phase 69 重新标定：sync 98 用例 TP=64/FP=0/FN=0，recall/precision 100%，FPR 0——此前本机退化 loopback 曾出现 1 例环境性假 FN，单跑该用例 0.2s 即检出；runner 现对出错用例自动重试，且**漏洞用例若最终无法完成计入 FN**，不再让跑不完的用例悄悄缩小 recall 分母。Phase 176n 补上这句话当时做不到的部分：旧闸门是 `verdict != "FN"`，**只有出错的漏洞用例被重试**，出错的安全用例首试即被接受、直接从分母消失；现由 `_evaluate_with_retries()` 两类一并重测（并发路径此前一次都不重试），产物并记录 `engine` / `retried_cases` / 每例 `retries`）。**注意该标定已被 Phase 91/92 刷新**：当时 async 基线里 3 个 safe 用例存在从未暴露的误报（Phase 84 引入），最新数字见文末「当前基线」表——precision 仍是 1.000，但 recall 分母口径下的 FN 需先单跑复现再判定。
- **SPA hash 路由自动发现（Phase 209）**：Angular/Vue 的 hash location strategy 只在
  `location.hash` 里读路由，HTTP 探针打服务端路径（`/search`）永远碰不到客户端 sink。
  现在从应用**自己的 bundle** 里配对 `navigate([/route], {queryParams:{…}})` → 得到
  路由与参数名 → 注册成 `origin/#/route?param=` 端点（上限 12），sync 静态爬取、
  sync SPA 爬取、async 爬取三条路径都接线。**外部效度实测**：OWASP Juice Shop 20.2.0
  （第三方真实应用，非本仓 fixture）上 `xssentinel -u <origin> -c --headless` 一条命令
  即报出 `dom_dynamic` **high/high browser-executed**（`location.hash` →
  `Element.innerHTML`，对应上游 `challenges.yml` 的 `localXssChallenge`）；双引擎各命中
  一个**不同**的真实 sink，且都经独立 Playwright 复核（注入 `<em class=…>` 后被解析成
  元素而非文本）。同一轮还量出并修掉一个 **critical 级假阳性**（模板 SSTI 把错误页栈
  行号里的 `49` 当成 `{{7*7}}` 的渲染结果），现为差分对照判定。
- **可复现 PoC**：每个确认漏洞自动产出 **curl 命令 + 含 payload 的 URL + 自包含 HTML PoC 页面**（iframe / 自动提交表单 / `location.hash` 触发 DOM），HTML/JSON/CSV/SARIF 四报告均携带，直接交差或进缺陷单。
- **被动代理扫描（Phase 44）**：`--passive` 起本地 HTTP 代理（对标 xray / w13scan 的被动模式），浏览器/工具挂代理即可把流量捕获进扫描流水线——按 `方法+主机+路径+参数名集合` 签名去重（分页/翻 token 不重扫），GET/POST 表单与 JSON body 全解析，HTTPS 默认走 CONNECT 隧道透传；加 `--mitm-ca ca.pem`（Phase 50）则自动生成本地 CA 并对 scope 内主机做 HTTPS 拦截——每主机证书由该 CA 签发，把 CA 证书 `ca-cert.pem` 装进浏览器/系统信任库后 HTTPS 参数/body 也能被捕获扫描（越 scope 主机保持盲透传）；后台 worker 把捕获端点直接喂给 L1 流水线，`--sqli-check` / `--check-outdated-js` 快检可联动（见下）。写端点（POST/PUT/PATCH）扫描后自动进入 **stored 二阶观察**：对 body 参数注入唯一 token 探针，之后浏览到的任意页面若原样渲染该 token（可执行上下文）即确认 high `second_order` finding——存储型 XSS 无需手动指定注入/查看端点（Phase 67）。
- **目标级 CORS / XS-Leaks 审计（Phase 51/53）**：每 origin 探测 Origin 反射（GET+OPTIONS 兜底）——反射任意 Origin+Allow-Credentials → high `cors_misconfig`；`--audit-xs-leaks` 对无任何跨源隔离头（COOP/CORP/COEP/帧守卫）的页面记 low `xs_leak_surface`；`xs_leaks.py` 另附 img/frame-timing/window.name/history 四信道载荷库与免服务器演示 PoC（证明已确认 XSS 的跨站窃取半径）。sync/async 双引擎对齐（Phase 54）。
- **生态导出保真（Phase 55）**：nuclei 导出按 finding 真实载体重放——query 反射走参数、上传走 multipart raw、`(header:X)`/`(cookie:X)` 走 raw 请求头/Cookie、path/error 走百分号编码路径（均有 nuclei live-MATCH 回归测试）；Burp XML 内嵌可复现请求。
- **SQLi 错误回显快检（Phase 44）**：`--sqli-check` 对标 dalfox grep 引擎 / xray sqldet——向每个参数注入 7 枚引号类探针，用 MySQL / PostgreSQL / MSSQL / Oracle / SQLite 五家族指纹正则匹配数据库错误回显（无回显不报），命中即报 finding 并停止该参数，先做 baseline 跳过本身就带 DB 错误的页面。
- **过时 JS 库扫描（Phase 44）**：`--check-outdated-js` 对标 XSStrike retireJS——解析 `<script src>`，版本提取锚定库名（`/static/v2/jquery.min.js` 的 v2 不误判为 jQuery 版本），比对 jQuery / AngularJS / Bootstrap / Vue / Underscore / Lodash / Handlebars 七库的已知 CVE 版本区间，命中即报 outdated_js_lib（medium/high）。
- **镜像页防护（Phase 78）**：param_miner 哨兵预探测（3 个随机哨兵全反射=镜像页，3 请求替代 100 候选洪水）+ 滚动反射比熔断（近 15 次 ≥85% 反射即 collapse，保留 1 个"任意参数"代表项）——吸收自 DalFox 2025 发现管线。
- **FUZZ 任意位置注入（Phase 79/80）**：`--fuzz-body '{"filter": FUZZ}' --fuzz-marker FUZZ` —— body 模板内任意位置（JWT 内层/XML 节点/深层 JSON 叶子）的标记全量替换注入，反射（raw/URL 编码）与确认（verbatim 未转义 + 危险形状）分级报告；`--fuzz-body @file` 支持模板文件。吸收自 DalFox FUZZ 模式。
- **BAV 联动探针（Phase 81/82）**：`--bav` —— 隐藏参数挖掘命中的参数顺带做三类相邻漏洞探测：SSTI（{{777*'7'}}→5439 唯一常数）、CRLF（注入响应头回显）、开放重定向（3xx Location 指向唯一 host），各一请求、无模糊启发式；确认项入报告（type `bav`）。吸收自 DalFox BAV 分析。
- **原始请求文件输入（Phase 83）**：`--raw-request captured.txt` —— Burp/ZAP "copy as raw" 格式直接作为扫描入口：方法/URL（Host 构造）/头/Cookie/body 全部回填后走完整扫描管线（认证/OOB/爬取/报告继承），无平行弱实现。对齐 DalFox `--rawdata`。
- **批量输入管道（Phase 87 P0）**：`--batch urls.txt` 与 `--batch-stdin`（管道流式喂入，一行一个 URL，# 注释）——侦察链（httpx/gau/wayback）输出可直接接进扫描器，URL 去重、失败目标不中断整批、按目标分报告。对齐 DalFox pipe 模式。
- **HAR 导入（Phase 88 P1）**：`--har capture.har` —— 浏览器 DevTools/Burp/ZAP 导出的 HTTP Archive 直接作为扫描入口：每个捕获请求展开为一个真实端点，method/form·JSON body/cookie/自定义头全部回填后走完整扫描管线（对齐 Burp/XSpear 的 HAR 入口）。
- **OpenAPI/Swagger 导入（Phase 89 P1）**：`--openapi spec.json` —— 文档化的 API 契约（OpenAPI 3.x / Swagger 2.0）直接作为扫描入口：每个 path+operation 展开为端点（含浏览器从未访问过的路由），路径模板 `{id}` 按 example/schema 链解析为样本 URL，form/JSON body 由 schema 构建，apiKey/bearer 安全声明转为请求头。与 HAR 互补：HAR 覆盖"实际流量"，OpenAPI 覆盖"声明面"。
- **抗劣化分批基准跑（Phase 44，Phase 91 扩参）**：`benchmark/run_benchmark_batched.py [out.json] [batch] [port] [sync|async] [max_payloads] [max_transforms] [timeout]` —— `run_benchmark.py` 在单进程内跑完 194 用例，遇到会间歇掐 loopback 的安全软件（WinError 10053/10054）时必然卡在中途（实测 7 次 0 完成）；分批版按小批（默认 6）评估、**每批落盘**、支持中断续跑与失败重试。位置参数 4-7 可选（默认 sync/10/6/45），传 `sync 14 12 90` 即复现标定口径；续跑时预算变了会丢弃旧结果。**Windows 本机跑完整矩阵请用这个入口**（默认预算 6–7 分钟全矩阵，14/12/90 口径 sync 约 12 分钟、async 约 25 分钟）。
- **凭据不外泄给被扫页面选定的源（Phase 189，对标 Dalfox GHSA-mph2-gf5w-6f9f 的修复）**：实测确认（requests 2.32.5 / urllib3 2.6.3 / aiohttp 3.13.3）跨源 302 时 urllib3 只按 **host 字符串**剥 `Authorization`/`Cookie`（`localhost→127.0.0.1` 算跨、`h:8080→h:9090` 不算），自定义头 `X-Api-Key` 与无 domain 的 `--cookie` 照发；aiohttp 头与 jar cookie 全发。也就是**被扫页面通过 `Location:` 决定操作者凭据送到哪些源**。现规则一条：凭据只跟着"操作者点名的源"走——顶层请求恒带，仅因响应 `Location:` 才到达的源收不到（同族 `--headers`/`--cookies`/`Authorization`/`Cookie` 全剥，`User-Agent` 等浏览器形状头保留，跨源链不再像扫描器）。LLM 池的 `Bearer` API key 改为不跟随重定向。重定向仍被跟随、响应体仍被解析，**判定语义零变化**。可选 `--stop-at-cross-origin` 把同一规则升级为**授权边界**：页面 `Location:` 指向未点名源时连载荷都不发过去（返回 3xx 本身并在运行末尾列出被拒绝的跳转）。实测对照：默认关时一次扫描把 40 余个探针带到第三方 loopback 源，开启后为 0 个；同域重定向照常跟随、照常带凭据。async 侧凭据剥离同样生效，但 aiohttp 的跳转循环无法中途终止，故"停止跟随"目前仅 sync 引擎——CLI 显式警告而不是假装支持。
- **CSP 交付家族粒度（Phase 189）**：`script-src-elem` / `script-src-attr` 不是"追加"到 `script-src`，而是对各自投递形态**替换**。原实现（`csp.analyze` / `is_strict_inline` / `gadget_chain_relevant` / `verifier._csp_blocks_inline`）一律只读 `script-src`，于是两个方向都错：`script-src 'self'; script-src-attr 'unsafe-inline'` 被判"内联全禁"（反射型 `onerror` 被否证 = FN，预算还被切到早停档），`script-src https://cdn.example.com`（没有 `'unsafe-inline'`）里的反射 `<script>` 被判可执行 = FP。nonce 的"使 `unsafe-inline` 失效"规则改为**按家族**判定：`script-src` 上的 nonce 不再吃掉 `script-src-attr` 里的 `unsafe-inline`。同时 `'unsafe-hashes'` 与 gadget 主机识别覆盖 `-elem`/`-attr` 列表。
- **净化器语料现代化（Phase 189）**：DOMPurify 版本线从"停在 2020（<2.0.8）"改为三段**修复线**（<2.0.8 mXSS／<3.1.3 原型污染+嵌套 mXSS／≤3.4.15 2026 集群），编号取自厂商 advisory 列表（GitHub API 实测 25 条，最新发布 3.4.16），并按"一个版本一条发现"去重（横幅注释与 npm 路径两种形态不再各报一次）。2026 年全部 advisory 的利用面都是**配置项**而非标签白名单，故新增 `IN_PLACE` / `CUSTOM_ELEMENT_HANDLING` / `SAFE_FOR_TEMPLATES` / `setConfig()` 持久化 / `USE_PROFILES` / `ADD_ATTR` 里的 `on*`（high）/ `ADD_URI_SAFE_ATTR` / `ALLOWED_URI_REGEXP` / `RETURN_TRUSTED_TYPE` 检测，且带"加固过的页面必须沉默"反向对照。
- **Source map 摄取（Phase 189，对标 nexa / ASTra 类 JS 源码挖掘）**：`//# sourceMappingURL=`（含 legacy `//@`、块注释形、`data:` 内联形）→ 取回 `.map` → `sourcesContent` 里的**未压缩原始源码**进既有 JS 端点/汇聚点挖矿通道（压缩改名的路由、被 tree-shake 掉的 API 路径只有在这里看得见）；能读回 `sourcesContent` 时另记一条 `source_map_exposed`（low）发现。两道硬限制：每个脚本最多取一个 map、引用指向别的源就不取（页面点名的 URL 不构成抓取授权）；非 JSON/超限 body 静默不炸挖矿。
- **多格式报告 + 并发**：HTML / JSON / CSV / **SARIF(2.1.0) / JUnit / Markdown** 六种文档格式 + Burp XML / nuclei 两种生态导出，SARIF 可直接接入 CI / 缺陷平台（如 GitHub code scanning、Defender、Jira）；多线程端点/参数并发扫描；报告与 PoC 产物在 POSIX 上以 **0600** 写出（Phase 326，产物含目标 URL/参数/载荷，共享主机上不应全局可读）。


</details>

**只用于你被授权测试的系统。**

> **第一次用？** 先看 [`docs/QUICKSTART.md`](docs/QUICKSTART.md)——三条命令、四个退出码、
> 四个会让人误读结果的环境陷阱。上面这份能力清单是**参考**，不是上手路径。

## 质量门禁（为什么可以信这份结果）

- **push 门**：64 例分层切片 × 双引擎，`--strict-gate` 要求 FP0 / FN0 / ERROR0；切片按 ISO 周轮转，49 周覆盖全 194 例矩阵（数字由 `tests/test_quick_gate_slice.py` 钉住）。
- **全量门**：全部 test_*.py 逐文件分批跑（`--jobs 4`，每文件独立超时 + 一次重试，失败证据随 CI 产物留存）。最近一次引用口径为 **274/274 文件有效绿**：**271 文件 in-gate 绿 + 3 个环境超时文件单跑复绿**，**skip 69 例 / 18 文件（其中 5 个整文件零贡献）**、1412s、exit 3——两组数与跳过数一起报；架构行数上限、宽泛吞异常棘轮等守卫做过变异对照（红→还原→绿）。
- **独立靶**：官方 XSSMaze 靶 + 官方 runner 同 scorer 三工具对跑，产物随仓库分发（见下「外部效度」）。

跑法与口径见 [CONTRIBUTING](CONTRIBUTING.md)「测试」一节与 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

---

## 外部参照：PortSwigger（Burp 官方）语料覆盖对照

自有基准再满分也只能证明"内部一致"。要回答"检测面够不够广"，需要一个**第三方撰写的权威向量集**——
[PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
（Burp Suite 厂商维护，业界公认最全）就是这个参照，且自带两项第三方标注：是否需要用户交互、适用上下文。

复现（cheat sheet 需自行抓取，本仓库不内联第三方内容）：

```bash
curl -o pw.html https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
python benchmark/portswigger_corpus_coverage.py --html pw.html \
    --json benchmark/results/portswigger_corpus_coverage.json
```

当前结果（2026-11-01 复跑，cheat sheet 快照 2026-09-30，产物 `benchmark/results/portswigger_corpus_coverage.json`；822 条向量，对照 `payloads.json` / `svg_xss.json` / `framework_xss.json`）：

| 分组 | 向量数 | 事件处理器覆盖 | 标签覆盖 | 协议覆盖 |
|---|---|---|---|---|
| **无需用户交互**（主指标） | 57 | **100%**（52/52，Phase 192 补齐 40 个缺失事件） | 100%（21/21，Phase 192 补齐 6 个缺失标签） | 100%（1/1） |
| 需用户交互（仅参考） | 520 | 73.1%（76/104，Phase 192 语料补齐后） | 74.4%（29/39） | 100%（2/2） |
| 其他（标签 / 框架 / 协议类） | 245 | **100%**（14/14，Phase 192） | 71.2%（37/52） | 100%（3/3） |

**为什么只把"无需用户交互"当主指标**：cheat sheet 穷举了浏览器整个事件面，其中一大半
（pointerdown / mousemove / mouseenter …）必须用户交互才触发，把它们算进分母会得出一个
误导性的低数字（Phase 192 语料补齐前，三组混算实测只有 15.4%）。公平口径是看注入即执行的那一组——Phase 192 起该组
**三维全部 100%**（2026-11-01 复跑确认）。

**这个数字不能说明什么**（别拿它自欺）：

- 字符串出现 ≠ 语义等价：语料里出现 `onanimationend` 不代表有一条能真正触发它的完整载荷；
- 覆盖 ≠ 能检出：这只测"检测面有没有提到这项技术"，不测端到端检出率；
- 忽略 PortSwigger 标注的浏览器支持差异。

缺口 top（2026-11-01 复跑口径）：`no_interaction` 组（主指标）三维缺口已**清零**；当前缺口集中在参考组——
`requires_interaction` 事件缺 28 个（`pageswap`、`formdata`、`auxclick`、`pagehide`、`gesturechange` 等）、
标签缺 10 个（`param`、`geolocation`、`noembed`、`xmp`、`noframes` 等）；`other` 组标签缺 15 个
（`x`、`frame`、`strong`、`frameset`、`thead`/`tfoot` 等）——多为需交互或纯展示标签，不影响主指标。


## 外部参照：同类开源扫描器同靶跑分（2026-10-04）

覆盖对照说明"检测面提到没提到"，它回答不了另一个问题：**同一批靶，别人扫得出多少**。
所以把 XSSentinel、[DalFox](https://github.com/hahwul/dalfox) 与
[nuclei](https://github.com/projectdiscovery/nuclei) 的官方 DAST XSS 模板放到**完全相同的
目标**上各跑一遍——同一个 URL 构造（含 cookie-tossing 用例需要的 `sub.localhost` host 别名）、
同一个探针值，逐例对照 manifest 里独立撰写的 ground truth。

```bash
# dalfox 经 Go 模块代理安装（落 $GOPATH/bin，适配器会自己找到）
go install github.com/hahwul/dalfox/v2@latest
python benchmark/run_cross_tool.py --sample 60 \
    --tools XSSentinel,dalfox,nuclei-dast-xss \
    --out benchmark/results/phase196_cross_tool.json \
    --md  benchmark/results/phase196_cross_tool.md
```

60 例是按 `(ground_truth, context)` 分层的确定性切片（64 个族各取一条，不靠随机种子）：

| 工具 | 版本 | TP | FP | TN | FN | ERR | recall | f1 | 墙钟 |
|---|---|---|---|---|---|---|---|---|---|
| **XSSentinel** | 本仓（与门禁同口径 14/12 预算） | 35 | 0 | 24 | 1 | 0 | 0.972 | **0.986** | 346s |
| DalFox | v2.13.0 | 26 | 1 | 22 | 10 | 1 | 0.722 | **0.825** | 1173s |
| nuclei（dast/xss 模板） | v3.9.0 | 26 | 0 | 23 | 10 | 1 | 0.722 | **0.839** | 49s |

**这张表的三条限定，缺一条就会被误读**：

- **目标仍是我们自己构造的**。判定语料（nuclei 模板、DalFox 载荷与挖掘策略）来自第三方，
  靶场不是——所以"别人出的题"只到位一半。真正的独立验证（真实应用、商业工具对跑）仍未做。
- **我方唯一那条 FN 是打分口径，不是漏检**：XS-Leaks 审计层按设计产出 low/firm 结论，
  而这里"检出"定义为 high/medium/critical 的 XSS 级 finding；这一层两个第三方工具根本没有。
- **速度不是单向优势**：nuclei 用 49s 拿到 0.839，比我们先完成 7 倍。任何"性能优于同类"的
  说法都得对着这一行校准。

ERR 记的是"没测到"（超时 / 该工具结构上无法接收这条用例的输入形状），不计入 TN/FN——
一次没跑成的扫描不该伪装成一个否证结论。

## Range #3 —— 第三方意见应用靶场

`range3/` 是一个刻意与 benchmark 异形的**应用**靶场:SQLite 持久化、登录会话与
401 门、混合内容类型(HTML/JSON/纯文本/UTF-7 旧字符集)、多反射点页面、RCDATA、
cookie/header 载体回显、base64/JWT 容器解码回显、存储型与二阶流、认证后反射、
CSP strict/nonce、DVWA 式分级防御(medium/high/impossible)。ground truth 从
**服务器行为**独立撰写;runner 驱动真实 CLI(双引擎)评分。

```bash
python range3/runner.py --engine both      # 全量 26 例,sync+async 各跑一轮
python range3/server.py 8902               # 单独起靶场(app 模式)
```

评分采用"服务器行为 = 真值":vulnerable/safe/low(JSON 反射必须保留但降置信)。
首轮即暴露 6 个扫描器缺陷(全部已修,见 AGENTS.md 178c);当前基线
**sync TP20/FP0/FN0,async TP17/FP0/FN0(2 SKIP 为 sync-only 载体)**。

## 检测架构（6 层）

```
L1  反射层    探针定位反射点 → 上下文分析(20+ 种) → 按上下文选 payload 并发射
L2  WAF 绕过   命中拦截 → 套用 28 个变形/编码家族生成变体 → 再尝试
L3  DOM 层     静态分析页面 JS：source( location/document/postMessage… ) → sink( innerHTML/eval/jQuery… )
L4  存储层     注入 → 重新拉取"展示页" → 确认持久化执行
L5  盲打层     (可选)为每处注入生成唯一 token 的 OOB payload → 轮询回调监听 → 收到 beacon 即"已确认"盲打
L6  无头/DOM   (可选)Playwright 真实渲染：① 对 DOM sink 插桩并注入唯一标记，标记流入 sink 即"已确认"DOM XSS；
        动态确认   ② 捕获 dialog 事件作为反射型铁证
        │
        └─ 每层结果都经过"语义确认"：注入唯一 token，确认它落在真实可执行位置
           而非仅被原样回显（可有效识别 html.escape 后的伪漏洞）

发现层（串联上述检测层）：
  • 深度爬虫  -c（BFS，--crawl-depth 控制深度，--scope 限域）：自动发现同域
             <a> 链接与 <form> 端点，连无参数的纯 DOM 页面也纳入扫描。
  • 去重      dedup()：按 (type, URL, param, context) 合并多路径/多变形发现的同一
             漏洞，避免重复告警（DOM 类忽略 query 差异）。
  • 可复现 PoC - 每个确认漏洞自动生成 curl 命令、含 payload 的 URL、以及自包含
             HTML PoC 页面（iframe / 自动提交表单 / location.hash 触发 DOM），
             直接交给同事或写进报告。
```

---

## 安装

```bash
cd xssentinel
python -m venv .venv && .venv\Scripts\activate     # Windows
#   或：source .venv/bin/activate                  # Linux/macOS
pip install -e .                                   # 依赖：requests, beautifulsoup4
```

可选（用于 L6 无头浏览器确认）：
```bash
pip install playwright && playwright install chromium
```

> **需要 Python 3.10+**：3.9 已 EOL，且 requests / urllib3 / aiohttp /
> soupsieve 的修复版均要求 Python ≥3.10；在 3.9 上全新安装仍会解析到带已知
> advisory 的旧版本（实测见 [docs/DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md)）。
> 自 Phase 328d 起不再支持 3.9（CI 使用 3.11，另有 3.10 下限冒烟门）。

> **发布状态（2026-11-04）**：本项目**尚未发布到 PyPI**
> （`pypi.org/project/xssentinel` 返回 404），当前请使用上面的源码安装方式。
> `.github/workflows/pypi-publish.yml` 已就绪，但需仓库归属者在 pypi.org 完成
> 一次性 Trusted Publisher 配置，之后推送 `v*` tag 才会真正上传；配置完成前
> publish job 会以 403 失败。Beta 成熟度与能力边界见上文「定位与诚实声明」。

---

## 快速使用

### 命令行

四个程序模式各有一个名字（Phase 344）：`scan`（默认）、`serve`、`selftest`、`mcp`。
子命令是**纯语法糖**——它只是被替换成原本就存在的 flag，所以两种写法完全等价，
现有脚本一行不用改：

```bash
xssentinel scan -u "https://t.com/search?q=test"   # == xssentinel -u ...
xssentinel serve --port 8000                       # == xssentinel --serve ...
xssentinel selftest                                # == xssentinel --self-test
xssentinel mcp                                     # == xssentinel --mcp
```

`scan --help` 仍是完整列表（参数总数由 `--help` 构建时自算并印在页首——扫描确实
需要这么多）；`serve` / `selftest` / `mcp` 的 `--help` 只显示各自用到的参数，
650 行的墙缩到一屏内（上限 <60 行由 `tests/test_cli_subcommands.py` 钉住）。
**隐藏只影响显示**：`xssentinel serve --headless` 照样能解析。

```bash
# 扫描单个 GET 参数（自动从 URL ?q= 提取）
python -m xssentinel -u "https://example.com/search?q=test" -o report.html

# POST 表单
python -m xssentinel -u "https://example.com/comment" -m POST -d "name=x&bio=y"

# 带认证 / 代理
python -m xssentinel -u "https://example.com/p" -H "Authorization: Bearer <TOKEN>" -b "session=yyy"

# 表单登录（认证感知爬取）：登录成功后 cookie/token 自动携带，会话丢失自动重登
python -m xssentinel -u "https://example.com/app" -c \
  --login-url "https://example.com/login" --login-user user --login-pass pass \
  --login-field-user username --login-field-pass password \
  --login-success-marker "dashboard" --auth-relogin-on-loss

# 断点续扫：大站中断后从检查点继续（已扫端点不重扫）
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json
python -m xssentinel -u "https://example.com" -c --checkpoint cp.json --resume

# 爬取表单与链接后逐个扫描（默认深度 2）
python -m xssentinel -u "https://example.com" -c

# 深度爬虫：加大深度 + 限定 scope 前缀（只爬该路径下的同域页面）
python -m xssentinel -u "https://example.com/app" -c --crawl-depth 3 --scope "https://example.com/app"

# 深度爬虫会去重并自动为每个确认漏洞生成可复现 PoC（见报告 PoC 列）

# 真·浏览器确认（需 playwright）
python -m xssentinel -u "https://example.com/search?q=test" --headless

# DOM-XSS 引擎选择（默认 auto：装了 playwright 就用真浏览器确认，否则退化为静态启发式）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine auto
# 强制使用真浏览器（未装 playwright 会优雅降级，仍给出静态结论）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine playwright
# 仅用静态启发式（不启动浏览器，最快）
python -m xssentinel -u "https://example.com/search?q=test" --dom-engine static

# 多格式报告（-f 支持 html,json,csv,sarif,junit,markdown,burp,nuclei）
python -m xssentinel -u "https://example.com/search?q=test" -f json -o report.json
python -m xssentinel -u "https://example.com/search?q=test" -f sarif -o report.sarif

# 存储型 XSS（显式指定注入 /store、回读 /view；不指定时 sync 默认自动发现注入点）
python -m xssentinel -u "https://example.com/p" --stored-inject https://example.com/store --stored-view https://example.com/view

# 盲打 XSS 自动确认（自托管监听器，离线/测试用，收到 beacon 即确认）
python -m xssentinel -u "https://example.com/search?q=test" --oob self

# 盲打 XSS 自动确认（公共 interactsh 服务器，真实场景）
python -m xssentinel -u "https://example.com/search?q=test" --oob interactsh

# 并发扫描（4 线程）
python -m xssentinel -u "https://example.com/search?q=test" --threads 4

# 异步引擎（aiohttp 高吞吐多目标）。缺 aiohttp 时默认回退 sync，但**回退会写进产物**：
# 报告顶层 engine / engine_fallback_reason 两个字段说明「这次是谁跑的、为什么不是它」
python -m xssentinel -u "https://example.com/search?q=test" --async

# 流水线要求「产物必须来自异步引擎」时用 --require-async：缺依赖直接 exit 3，
# 绝不静默降级（对比 sync 与 async 基线时，这条能挡住"引擎不同被当成检出差异"）
python -m xssentinel -u "https://example.com/search?q=test" --require-async -f json -o r.json

# 声明式多步场景（存储流等；JSON 配置，Nuclei 风格）
python -m xssentinel -u "https://example.com/comment" --scenarios my_scenarios.json

# 被动代理扫描：浏览器/工具挂本代理，流量自动进扫描流水线（对标 xray/w13scan）
python -m xssentinel --passive --proxy-port 8080 --sqli-check --check-outdated-js
#   浏览器设置 HTTP 代理 http://127.0.0.1:8080 即可；HTTPS 默认 CONNECT 隧道透传
#   --mitm-ca mitm/ca.pem 开启 HTTPS 拦截（自动生成 CA）；先装 mitm/ca-cert.pem 到信任库
#   捕获端点按 方法+主机+路径+参数名集合 去重，Ctrl+C 退出并写出报告
#   multipart 上传请求的文件字段会被自动识别并路由到上传 filename XSS 探针

# 上传 filename XSS（sync 与 --async 通用；--upload-field 可重复给出多个字段）
python -m xssentinel -u "https://example.com/up" -m POST --upload-field file

# SQLi 错误回显快检（对标 dalfox grep 引擎，独立模式）
python -m xssentinel -u "https://example.com/search?q=1" --sqli-check

# 过时 JS 库扫描（对标 XSStrike retireJS）
python -m xssentinel -u "https://example.com" --check-outdated-js
```

常用参数：`-m/--method`、`-d/--data`、`-c/--crawl`、`--headless`、`--timeout`、
`--scan-policy {quick,normal,deep}`（策略预设，显式 flag 覆盖预设；max-transforms / max-payloads / threads 的默认值由预设档位决定——normal 档为 12 / 10 / 4，quick 档更低，显式传参始终优先）、
`--max-transforms`（绕过变体数，随预设档位）、`--max-payloads`（每上下文最大 payload 数，随预设档位）、
`--threads`（并发线程数，随预设档位）、
`--async` / `--require-async`（异步引擎；后者要求产物必须来自异步引擎，缺 aiohttp 时
exit 3 而不是回退 sync——报告顶层恒带 `engine` 与 `engine_fallback_reason`）、
`--oob {self,interactsh}`（盲打自动确认模式）、
`--oob-timeout`（等待回调秒数，默认 12）、
`--dom-engine {auto,playwright,static}`（DOM-XSS 引擎：auto=有 playwright 用真浏览器确认、否则静态；playwright=强制真浏览器；static=仅静态启发式，默认 auto）、
`--stored-inject` / `--stored-view` / `--stored-param`（存储型扫描；sync 默认开存储注入点自动发现，`--no-stored-auto` 关闭，显式 `--stored-inject` 时自动让位）、
`-o/--output`、`-f/--format {html,json,csv,sarif,junit,markdown,burp,nuclei}`（burp=Burp XML、nuclei=每 finding 一个可运行模板目录）、
`--upload-field`（上传 filename XSS，见上）、
`--audit-xs-leaks`（XS-Leaks 表面审计：无 COOP/CORP/COEP/帧守卫的页面记 low）、
`--login-*` / `--oauth-*` / `--auth-*`（认证感知爬取，见上）、
`--checkpoint` / `--resume`（断点续扫）、`--rate-limit`（全局限速）、
`--proxy` / `--proxy-list`（出口代理/轮换）、`--rotate-headers` / `--jitter-ratio`（指纹与节奏扰动）、
`--second-order-*`（二次注入：注入点与查看点分离的存储型流）、
`--verify-fix` / `--diff`（对 JSON 报告重放确认修复情况）、
`--no-verify-ssl`。

**CLI 管道兼容（Phase 359 / 360）**——被智能体 / CI / shell 管道直接调用时的约定：

```bash
httpx -l targets.txt | xssentinel --batch-stdin -o - -f json | jq -c '.findings[]'
```

- `-o -` 把报告写进 **stdout**（UTF-8 字节）：单目标一行 JSON，批处理为 JSONL
  （每行一个目标，仅 `-f json`）；摘要 / 进度 / 错误全部走 stderr，`| jq` 拿到的
  只有报告帧。`-f nuclei` 写目录，不支持 stdout。
- `-o reports/scan.json` 自动创建缺失的父目录（旧行为是写失败并误报 exit 3）。
- `--batch` / `--batch-stdin` 接受 UTF-8（带/不带 BOM）、UTF-16（BOM）、
  GB18030/GBK 与 CRLF；无法解码时给明确错误，不再抛 traceback。
- 退出码：`0` 成功、`1` 崩溃、`2` 用法/输入错误、`3` 扫描不完整（此时"无发现"
  不是"无漏洞"）。无目标时 stdout 为空、错误在 stderr，不再倾倒整页 `--help`。
- **Phase 360 补齐**：`--version` / `-V` 输出单行版本；`--ver` 仍等价于
  `--verbose`（新增 `--version` 不会让历史缩写变成歧义错误）。`--config` 与
  `--batch` 共用同一套输入解码（UTF-8 BOM / UTF-16 / GB18030），坏配置回 rc=2
  + 明确原因，不再静默变成空配置或抛 traceback；配置里的 `format` / `timeout` /
  `output` 等键现在生效（显式 CLI flag 仍优先，见 CHANGELOG 的 Changed 条目）。
- `-o - -f nuclei` 与批量非 JSON 一样在**扫描开始前**回 rc=2；下游提前关闭管道
  （`... | head`）视为正常结束（rc=0、stderr 一行说明），不再把剩余目标误报成
  "扫描不完整"。所有人类文本在 `-o -` 时统一走 stderr（`__main__` /
  `cli_runner` / `cli_commands` 三个模块由源码级守卫钉住),非 `-o -` 时
  stdout 字节不变。
- **功能面审计(Phase 360 后续)**:29 个功能面用例与 133 个 flag 各经真实
  CLI 子进程调过一遍,0 崩溃 / 0 超时,8 种报告格式全部产出文件。坏
  `--raw-request`、损坏的 `--resume` checkpoint、`--poc-dir` 目录不可用都回
  诚实错误而不再 traceback 或误报 exit 3;`--ai-timeout` 现在对 `--ai-check`
  生效;`--self-test` 自动避开被占用的 8899。审计覆盖**入口可达性**,不等于
  所有 flag 组合的语义正确性(那由各功能专属测试与 194 例基准负责)。
- **`-o -` 全入口收口(Phase 362 后续,2026-11-06)**:扫描、`--diff`、
  `--verify-fix` 三个报告入口共用同一 stdout 帧;`-o -` 不再把 `-` 当文件名,
  CWD 不会出现 `-` / `-.json` / `-.csv`(根目录 11-05 的历史残留已删除,
  回归测试在临时 CWD 断言三者为空)。
- **XSSMaze 残余 FN(Phase 361–362)**:69 条 FN 逐条归因后修掉可修项
  (path 整段替换、UTF-7 charset 门、括号死页裸属性名语料);修后 194 例
  双引擎判定与改前逐位一致,27/27 控制例 FP=0,详见 CHANGELOG。

**批量输入（Phase 87 P0/P1）：**

```bash
# 批量 URL 文件（每行一个，# 注释）→ 每个目标一份报告到 -o DIR
python -m xssentinel --batch urls.txt -o reports/

# 管道输入：侦察工具直接流式喂入（httpx/gau/wayback 输出兼容）
# （Pipe mode，一行一个 URL；TTY 下会提示需要管道输入）
httpx -l in.txt | python -m xssentinel --batch-stdin -o reports/

# HAR 导入：浏览器 DevTools / Burp / ZAP 导出的 .har 直接作为扫描入口
# 每个捕获到的请求 = 一个真实端点：method/form·JSON body/cookie/自定义头
# 全部回填后走完整扫描管线（对齐 Burp/XSpear 的 HAR 入口）
python -m xssentinel --har capture.har -o reports/ -f json

# OpenAPI/Swagger 导入：文档化的 API 契约直接作为扫描入口
# 每个 path+operation = 一个端点（含浏览器从未访问的路由）；路径模板
# {id} 解析为样本 URL，body 由 schema 构建，apiKey/bearer 转为请求头
python -m xssentinel --openapi openapi.json -o reports/ -f json
```

**站点地图导入（Phase 184，DalFox 同款）**——sitemap index / urlset / 纯文本
sitemap.txt 都吃，`<loc>` 越域 URL 按 HAR 同款 scope 规则丢弃：

```bash
python -m xssentinel --sitemap https://target.com/sitemap.xml -o reports/ -f json
```

**Wayback 历史URL导入（Phase 192，gau/waymore 管道一键化）**——域名（可带路径
前缀收窄）查 Internet Archive CDX API，历史捕获过的 URL 全部成为扫描目标；
`fl=original` + `collapse=urlkey` + `statuscode:200` 过滤，越域 URL 同样按
scope 规则丢弃：

```bash
python -m xssentinel --wayback target.com -o reports/ -f json
# 路径前缀收窄：--wayback target.com/app
```

**MCP stdio server（Phase 192/202/322/323，dalfox v3 同款）**——把扫描器作为工具暴露给
LLM Agent（JSON-RPC over stdin/stdout），七个核心工具覆盖「侦察 → 扫描 → 调整重试」
全链路（2025-26 Agent 工具的主流形态是细粒度可组合，不是单一巨型调用）。
声明现代协议版本 `2026-07-28` 的客户端另有 2 个异步工具
（`xssentinel_scan_async` / `xssentinel_scan_status`，Phase 377）；legacy
`tools/list` 仍逐字节是那七个工具。
**参数契约（Phase 323，对标 dalfox v3.2.4 #1464/#1513 的语义级修复）**：`tools/call`
按各工具 inputSchema 校验参数——**未知键 = isError + 可接受键名清单，永不静默丢弃**
（拼错的 `cookies` 曾会让扫描不带认证跑完、回一份假"无发现"）；REST 同义拼写
（`target`/`cookie`/`header`/`body`/`parameter`）与 JS 驼峰（`maxPayloads`）先归一
到规范名再校验，canonical 与 alias 并存时 canonical 赢；integer 收数字串、enum
大小写不敏感，其余错误形状诚实报错、一轮可自我纠正：

```bash
python -m xssentinel --mcp
# 侦察链
# xssentinel_discover    无头渲染一次,回 SPA 表单字段名 + 同源 API 端点
# xssentinel_profile     单请求反射画像(context + raw=/stripped=/encoded= 元字符分类)
# xssentinel_param_mine  差分探测挖隐藏参数(Arjun 血统,一次一名有界)
# xssentinel_csp_analyze 一次请求读双通道(header+<meta>)CSP,按投递家族报内联放行
# 扫描与验证
# xssentinel_scan        全量扫描,返回压缩后的 finding 判定,无发现=成功
# xssentinel_verify      回放单条 Agent 自选载荷(同一确定性判定器;Agent 的调整-重试循环)
# xssentinel_propose     LLM 提议候选载荷,每条都经 token oracle 重放裁决——
#                        confirmed=令牌执行,永远不是模型说了算(pool 未配置则诚实报错)
```

**远程 MCP（Phase 324，Streamable HTTP）**——同一套 JSON-RPC 分发也挂在 REST API 的
`POST /mcp` 上，按 URL 挂工具的 Agent 平台（ARTEX / Claude / Cursor 类）无需起子进程：

```bash
python -m xssentinel --serve --host 127.0.0.1 --port 8080      # 生产建议再加 --api-key
# MCP 客户端配置：url = http://127.0.0.1:8080/mcp（配置了 --api-key 时加 X-API-Key 头）
```

传输形态：单条或批量 JSON-RPC 数组（逐条响应）；全通知批量回 202 空体；畸形 JSON
回 JSON-RPC `-32700`（不是 HTTP 400）；GET/DELETE `/mcp` 为 405（不提供 SSE 升级、
无 session 可删）。安全层与 REST 同一套：`--api-key`、同源门（跨源 POST 403）、
无 key 时 Host 限本机。**结构化输出（Phase 324）**：所有工具（含现代帧的 2 个
异步工具）都带 `outputSchema`，
成功结果额外携带 `structuredContent`（与文本内容同一对象；错误结果只回文本）。
**进度与取消（Phase 325，stdio）**：`tools/call` 的 `_meta.progressToken` 会收到
`notifications/progress`（progress = 已发请求数 + 起始信标）；`notifications/cancelled`
按 request id 中止（下一个请求处停，被取消的请求**不回响应**——MCP 规范）。
**长扫描（Phase 377，仅现代帧）**：单次 `tools/call` 会被宿主在 30–120s 掐断时，
改用 `xssentinel_scan_async` 提交——它**当场返回 `scan_id`、不发任何目标请求**，
再轮询 `xssentinel_scan_status` 直到 `terminal`。取回的是与 `xssentinel_scan`
同一份 compact findings，连 `truncated` / `total_findings` /
`effective_max_seconds` 一起透传；`cancel=true` 可中止，**失败或被取消的 job
绝不记成「无发现」**。job 复用既有 REST `JobManager` 状态机（内存态、有上限），
进程重启后旧 `scan_id` 失效。
**重试幂等（Phase 378，仅现代帧）**：宿主超时后重发**完全相同**的
`tools/call`，服务端在 60s 内复用上一次**成功**结果，不再重复外发攻击载荷；
结果的 text 与 `structuredContent` 同步带 `cache_hit` / `cache_scope` /
`cache_ttl_ms`。键包含归一化后的全部参数（含 `headers` / `cookies`），
不同认证上下文不会串结果；可用 `params._meta.requestKey` 指定键、
`cacheScope='none'` 关闭、`cacheTtlMs` 调 TTL（上限 300s）。失败 / 超时 /
取消**不缓存**，`xssentinel_scan_status` 轮询永不复用；legacy 帧逐字节不变。
`server/discover` 的 `resultReuse` 会声明当前策略。
**Agent 面默认与信任边界（Phase 328/328e）**：`xssentinel_scan` 默认与 CLI normal 对齐
（`dom_engine=auto`、`max_transforms=12`；DOM 层默认运行，Playwright 缺失时静态降级，
`headless` 只负责浏览器确认）。每个工具在 `untrusted_fields` 里列出自己由目标派生的
字段（scan: evidence/detail/param/waf；discover: 字段名/端点/路由；profile:
context/meta chars；verify: context/语义/无头详情；param_mine: discovered 行；csp:
families/weak_points/bypass_candidates），并带 `output_safety` 提示——Agent 应把这些
字段当数据，绝不当作指令。

**双协议接入（Phase 358）**——现行 MCP 规范 `2026-07-28` 去掉了 `initialize`
握手，把版本放进每个请求的 `params._meta.io.modelcontextprotocol/protocolVersion`，
并要求服务实现 `server/discover`。本服务是 **dual-era**：旧客户端照旧发
`initialize`（响应字节不变），现代客户端直接发现即可，无需握手：

```bash
# 现代客户端 stdio 探针（无需 initialize）
echo '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}' | python -m xssentinel mcp
# 旧版客户端配置不变：{"command":"python","args":["-m","xssentinel","mcp"]}
```

- 支持版本：`2024-11-05` / `2025-03-26` / `2025-06-18` / `2025-11-25` /
  `2026-07-28`。现代帧的结果带 `resultType` 与 `_meta.serverInfo`，
  `tools/list` 另有 `ttlMs` / `cacheScope`；未知版本回 `-32022` 并附
  `supported` 列表，不再静默降级。
- HTTP 现代帧：`MCP-Protocol-Version` / `Mcp-Method` 头与 body 不一致回
  `400` + `-32020`，未知方法回 `404` + `-32601`；缺头仍放行（兼容实现不完整的
  CLI）。旧帧的状态码一律不变。
- **stdio 固定 UTF-8 字节通道**：帧写底层 buffer，不受 Windows 控制台代码页
  （cp936/gbk）影响；靶场回显里的中文/emoji 不会再让写帧抛 `UnicodeEncodeError`。
- 明确不做：2026 规范的 MRTR、`subscriptions/listen`、SSE 流属于新能力，本轮
  只解决"连得上"，不引入新传输。

Agent 侧接入指南见 [skills/xssentinel-mcp/SKILL.md](skills/xssentinel-mcp/SKILL.md)。

**浏览器渲染输入发现（`--discover`，Phase 196）**——渲染目标一次：SPA 表单
字段名并入挖矿词表，页面自己 fetch 的同源 API 端点在主目标后扫描（上限 10）；
需要 playwright，sync 引擎专属。**已知边界（Phase 209 记录）**：`--discover` 目前
只回表单字段名与同源资源 URL，**不回 hash 路由表**——SPA 的 `/#/route?param=` 由
爬取路径（`-c`）发现并投递 DOM 探测，不走 `--discover`；把路由也暴露给
`xssentinel_discover`（供 Agent 编排）是排后的下一步。

```bash
python -m xssentinel -u "https://target.com/app" --discover -o reports/
```

**GraphQL introspection 输入面（`--gql`，Phase 195）**——schema 里 String 型
mutation 参数 / input 字段 / query 参数按写入侧优先并入挖矿词表，端点本身
成为扫描目标；与 `--stored-view` 配对即得 API 写入的存储型验证链：

```bash
python -m xssentinel --gql https://target.com/graphql -o reports/ -f json
```

**HPP 参数污染探针（`--hpp` 语义内建，Phase 193/196）**——检测到 WAF 且标准
梯子未确认时自动尝试：同参数投递两次（首现 benign、次现 payload），只查首现
的过滤器被绕过；query 与 form 体双位置。

**会话失效策略（`--session-check` / `--on-session-loss`，Phase 194）**——
响应体正则检测死会话（200 页写"请先登录"defeating 状态码检查）；
`--on-session-loss abort` 让死会话诚实停扫（findings 保留、原因记账）：

```bash
python -m xssentinel -u "https://target.com/admin" --login-url ...   --session-check "please log in" --on-session-loss abort
```

**跳过指定参数（`--skip-param`）**——命中的参数 L1/L2 不再探测、隐藏参数
挖矿也不再为其花费预算（挖矿默认额外跳过 utm_* / gclid / fbclid 等追踪
噪声；页面**已声明**的参数不受默认噪声表影响，仍会被主探针覆盖）：

```bash
python -m xssentinel -u "https://target.com/p?a=1&b=2" --skip-param "b,debug"
```

三个批量源（`--batch` / `--batch-stdin` / `--har` / `--openapi`）与 `-u` 互斥，报告均按目标
分文件写入 `-o DIR`；URL 去重、失败目标不中断整批、结束时汇总统计。

### 作为库调用

```python
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

sc = Scanner(requester=Requester(timeout=10))
sc.scan_target("https://example.com/search", method="GET", params={"q": "test"})
for f in sc.findings:
    print(f.data["type"], f.data["context"], f.data["payload"])
```

### 桌面控制台

```bash
xssentinel-desktop                 # 或: python -m xssentinel.desktop
```

一个进程、一个窗口：控制台页面由项目**自己的 REST API**（`xssentinel.api.server`）在进程内
伺服，窗口只是框住这个 origin。因此它不需要额外的服务进程，也不需要数据库或反向代理。

| 能力 | 说明 |
|---|---|
| 新建扫描 | URL / 方法 / 参数 / POST 体 / 请求头 / Cookie / DOM 引擎；快速-标准-深度预算预设；超时、限速、线程、爬取深度、Scope、代理、TLS 校验、自定义载荷 |
| 任务管理 | 实时/空闲自适应轮询、状态筛选与搜索、取消、删除、批量清理已结束任务、实时请求数/发现数 |
| 发现查看 | 严重度 + **证据类**（浏览器已执行 / OOB / 浏览器未复现 / 未用浏览器 / 语义确认）筛选、类型/文本过滤、分页、逐条展开；`dom_dynamic` 未观测执行时显式标注“投递证据”，不按已执行读 |
| PoC 操作 | 展开后可复制载荷、复制 curl、复制 PoC URL、在浏览器打开；报告页可一键打开或下载 |
| 报告 | HTML / JSON / SARIF / CSV / JUnit / Markdown 六格式 |
| 界面 | 明暗双主题（跟随系统，可切换）、响应式布局、键盘快捷键（Ctrl/⌘+Enter 开始、`/` 搜索）、页面响应带 CSP/X-Frame-Options/nosniff |
| API 密钥 | 右上角「密钥」弹层填入，仅存本标签页 `sessionStorage`；带密钥时报告走 fetch + blob 打开 |

**窗口后端按可用性递降**，三者都不需要额外服务：

1. `pywebview` —— 原生窗口（Windows 上走系统自带的 Edge WebView2）。装上即是：
   `pip install -e ".[desktop]"`；
2. `tkinter` —— Python 自带，本机必有；本机未装 pywebview 时它给出一个原生小窗，
   含地址、一键用浏览器打开、复制地址；
3. 系统默认浏览器 —— 零依赖兜底。

**安全边界**：只允许绑定回环地址（`127.0.0.1` / `localhost` / `::1`），
`--host 0.0.0.0` 直接拒绝并提示改用 `xssentinel --serve`；端口默认 `0`（自动分配），
不会与已有的 `--serve` 部署冲突。控制台页面与 API 同源——这正是 API 的
same-origin 门（Phase 70）所要求的，`file://` 页面会被所有变更类调用拒绝。
控制台响应另带 `Content-Security-Policy`、`X-Frame-Options: DENY`、
`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer` 与
`Cache-Control: no-store`，避免把扫描结果页变成可嵌入/可嗅探的载体。

其他用法：

```bash
xssentinel-desktop --no-window     # 只起 API 并打印地址（脚本/排查用）
xssentinel-desktop --port 8787     # 固定端口
xssentinel-desktop --backend tkinter   # 强制窗口后端
xssentinel-desktop --print-url-only    # 只打印 URL 后退出（自动化）
```

---

## 目录结构

```
xssentinel/
├── __main__.py            # CLI 入口（参数定义/策略预设/main 分发；Phase 43 拆分）
├── cli_runner.py            # 扫描执行：单目标 / async 单目标 / async 批量 / 报告写出
├── cli_commands.py          # 子命令：self-test / serve / verify-fix / diff / passive（Phase 44）
├── data/
│   └── payloads.json      # 上下文分类的 payload 语料（可自由扩展）
└── core/
    ├── requester.py       # HTTP 层（会话/代理/超时/SSL）
    ├── context.py         # 反射点上下文分析器
    ├── reflection_profile.py  # 反射画像（三明治探针 + 字符过滤反馈闭环）
    ├── generator.py       # 生成式 payload 构造器（仅用存活字符拼装）
    ├── pre_encode.py      # 自动预编码管道（base64/JWT/JSON 容器同构注入）
    ├── payloads.py        # payload 语料加载与按上下文检索
    ├── transform.py       # 28 个 WAF 绕过变形/编码家族（REGISTRY 为准）
    ├── waf.py             # WAF/拦截指纹识别
    ├── verifier.py        # 语义确认 + 无头确认（BeautifulSoup 结构化判定）
    ├── dom.py             # DOM XSS 静态污点分析
    ├── dom_engine.py      # DOM XSS 真·浏览器执行确认（Playwright 插桩 + 标记溯源）
    ├── poc.py             # 可复现 PoC 生成（curl / URL / 自包含 HTML）
    ├── scanner.py         # Scanner 核心类（L1 流水线/确认/去重；Phase 40 起
    │   │                  #  与 StoredBlind/AdvancedLayer/Crawl 三个 Mixin 组合）
    ├── scanner_stored.py  # StoredBlindMixin：L4 存储两步 + L5 盲打 OOB 收网
    ├── scanner_layers.py  # AdvancedLayerMixin：L3 DOM + L7 jsonp/csp/cors/mXSS/
    │   │                  #  clobber/template/polyglot
    ├── scanner_crawl.py   # CrawlMixin：SPA 无头爬取 + 隐藏参数挖掘 + BFS
    ├── async_scanner.py   # AsyncScanner 核心（Phase 191 起 = 编排 + _probe_param
    │   │                  #  + 传输/会话/预算三块，与下面三个 Mixin 组合）
    ├── async_scanner_verify.py  # AsyncHeadlessVerifyMixin：--headless 逐 finding 确认
    ├── async_scanner_layers.py  # AsyncDetectionLayersMixin：预编码/DOM/高级层/请求层/
    │   │                  #  CSP/CORS/XS-Leaks/上传/JSONP/盲打收网
    ├── async_scanner_crawl.py   # AsyncCrawlMixin：隐藏参数挖掘 + 端点/source map 挖掘 + BFS
    ├── async_scanner_common.py  # 共享 helper：egress cookie jar、非 HTML 降级、
    │   │                  #  JSONP 回调名、_AsyncScannerShim…
    ├── cors_check.py      # 目标级 CORS 审计（Phase 51：Origin 反射 + 凭据判定）
    ├── xs_leaks.py        # XS-Leaks（Phase 53：隔离头审计 + 通道载荷库/演示 PoC）
    ├── findings.py        # Finding 数据类 + 默认变形阶梯（mixins 共享）
    ├── scenarios.py       # 声明式多步检测场景引擎（--scenarios，Nuclei 风格）
    ├── passive_proxy.py   # 被动代理扫描（Phase 44：捕获→去重→喂 L1，对标 xray/w13scan）
    ├── sqli.py            # SQLi 错误回显 grep 引擎（Phase 44，对标 dalfox/xray sqldet）
    ├── retire_js.py       # 过时 JS 库扫描（Phase 44，对标 XSStrike retireJS）
    ├── layers/            # 高级检测层实现包（Phase 39 拆分）
    │   ├── client_layers.py     # postMessage/原型污染/SW/Worker/重定向/框架/GraphQL/WS
    │   ├── transport_layers.py  # header/path/cookie/error 注入
    │   ├── content_layers.py    # markdown/TT/CSP nonce/cookie tossing/SRI/import map
    │   │                        # sanitizer/CSSI/dangling markup/SVG
    │   └── common.py            # 共享 _make_finding
    ├── advanced_layers.py # 高级层门面（run_* 入口 + 向后兼容 re-export）
    ├── fix_advice.py      # 修复建议引擎（语料在 data/fix_advice.json）
    └── report.py          # HTML / JSON / CSV / SARIF / JUnit / Markdown 报告（含 PoC 渲染）
├── api/                   # REST API（--serve）：stdlib / Flask 双前端、任务队列、
│   │                      #  持久化、webhook、metrics、MCP server
└── desktop/               # 桌面控制台：进程内 API + 单页 UI + 窗口后端
    ├── app.py             #   入口：装 UI 路由、起 API 线程、开窗口、关停
    ├── shell.py           #   窗口后端 pywebview → tkinter → 系统浏览器
    ├── assets.py          #   UI 页面定位与加载（含缺失时的说明页）
    └── ui/index.html      #   控制台单页（原生 JS，无构建步骤）
tests/
├── vuln_server.py         # 本地脆弱测试服务（自测用，含 WAF 模拟端点）
├── run_self_test.py       # 逐层自检脚本
└── demo_scan.py           # 生成综合演示报告 demo_report.html / .json
```

---

## 自检 & 演示

本仓库自带一个**仅用于本地验证**的脆弱服务器，覆盖全部检测上下文：

```bash
# 终端 1：启动测试服务
python tests/vuln_server.py          # http://127.0.0.1:8899

# 终端 2：逐层自检（/safe 必须 0 命中）
python tests/run_self_test.py

# 生成综合报告
python tests/demo_scan.py            # 产出 tests/demo_report.html / .json

# 靶场 2：真实世界风格场景（半破损过滤器/上下文陷阱/二级存储/CSP nonce 泄露/
# DOM srcdoc·cookie·name 变体，Playwright 全链路确认）
python tests/run_range2.py           # 20 用例自动判定 TP/TN/FP/FN

# 被动代理演示（Phase 44）：起内建 origin + 被动代理 + 真实 Scanner，
# 回放 3 个浏览器式请求，验证 捕获→去重→扫描→发现→报告 全链路（含 /safe 零误报自检）
python tests/passive_demo.py         # 产出 tests/passive_demo_report.html
```

端点含义：`/echo`(HTML 元素)、`/attr`(双引号属性)、`/script`(脚本字符串)、
`/href`(href URI)、`/evt`(事件处理器)、`/dom`(DOM 污点)、
`/waf`(模拟 WAF 拦截 `<script>`，验证绕过层)、`/cdata`(CDATA 反射)、
`/meta`(meta-refresh 反射)、`/tpl`(`{{ }}` 模板反射)、
`/store`+`/view`(存储型 XSS)、`/safe`(html.escape，必须零误报)、
`/links`(爬虫 fixture：链接到上述多个端点 + POST 表单，用于验证深度爬虫/去重/PoC)。

验证结果（本地，全部层开启）：约 17 个发现（含反射 / DOM 动态确认 / 存储 / 盲打），WAF 被正确指纹识别，
`/safe` 端点在改进确认逻辑与盲打门控后**零误报**。`tests/run_self_test.py` 会断言每层均触发、`/safe` 为零（含 L6 真浏览器 DOM 确认），并单独用深度爬虫扫描 `/links` 验证发现去重与可复现 PoC 生成。

靶场 2（`tests/range2_server.py` + `tests/run_range2.py`）覆盖 benchmark 矩阵之外的真实世界缺陷：递归剥 script、单引号属性、onload 黑名单、空格过滤、mXSS 变异、未闭合引号属性、`--!>` 注释断点、正则字面量上下文、二级存储、**CSP nonce 泄露自动利用**（读取页内泄露的 nonce 构造同 nonce script，验证器对「nonce 与响应 CSP 头一致」的 script 放行——nonce 轮换的服务器不会被误确认）、iframe.srcdoc / cookie / window.name / 多跳 innerHTML 等 DOM 变体。当前成绩 **20 漏洞全报 / 6 安全零误报**（含 second_order 注入/查看双端点路径）——Phase 63 扩容后新增四类真实世界场景：JSON API（application/json 载体按文档 leaf 探测）、RESTful PUT multipart 上传 filename、CORS Origin 反射 + Allow-Credentials（high cors_misconfig）、XS-Leaks 无隔离面（--audit-xs-leaks 记 low），以及一个带 COOP/CORP/COEP 隔离头的安全负样本。

---

## 门禁与基线（当前口径）

逐 Phase 的工程过程叙事（各代基线、基准暴露的缺陷家族、自我纠正记录）已归档至
[docs/archive/README_phase_log_to_20261101.md](docs/archive/README_phase_log_to_20261101.md)；
历史数字只在带日期的记录里成立，当前口径以下述为准。全量分批回归门禁的跑法与
口径见 [CONTRIBUTING](CONTRIBUTING.md)「测试」一节。

### push 精度门禁（64 例分层切片，双引擎零容错）

`python -m benchmark.runner --quick` 取「每个 `(ground_truth, context)` 族一条」=
**64 例**，覆盖 manifest 全部上下文族；`--strict-gate` 要求 **FP0 / FN0 / ERROR0**
（ERROR 也算失败：没测到的用例不能让门禁"绿"得像是测过了）。切片按 **ISO 周**
轮转（`--quick-offset`）：最大族 49 例，49 次轮转覆盖全部 194 例；同一周内所有
构建是同一批用例（红绿差异可归因），跨周换批。本地复现某次 CI：

```bash
python -m benchmark.runner --quick --quick-offset <N> --engine sync
```

切片大小与轮转不变量由 `tests/test_quick_gate_slice.py` 锁定（含"CI / CONTRIBUTING /
README / OPTIMIZATION 里写的切片数字 == 代码实际产生的数字"）。

### 当前基线（Phase 304，194 用例矩阵，双引擎同一口径 14/12/90）

| 引擎 | 用例 | 计分 | TP | FP | TN | FN | ERROR | SKIP | recall | precision | 墙钟 | 产物 |
|------|------|------|----|----|----|----|-------|------|--------|-----------|------|------|
| sync | 194 | 194 | 113 | 0 | 81 | 0 | 0 | 0 | 1.000 | 1.000 | 858.36s | `benchmark/results/xssmaze_tagaware_20261023_sync.json` |
| async | 194 | 182 | 107 | 0 | 75 | 0 | 0 | 12 | 1.000 | 1.000 | 756.0s | `benchmark/results/xssmaze_tagaware_20261023_async.json` |

async 的 12 个 SKIP = stored 6 + upload 2 + second-order 2 + scenario 2，manifest
声明 `engines:["sync"]`。**SKIP 不是通过，也不是漏报。**

### 外部效度（XSSMaze v0.3.0，2026-10-24 终态）

第三方靶自带 official runner，ground truth 来自靶自身的 `/map/json`；口径是
"对照例上的任何 finding 记 FP，population 上的 low finding 也计检出"：

| 群体 | TP | FN | FP | P | R | F1 |
|---|---|---|---|---|---|---|
| client（`--reach client --headless`） | 24 | 0 | **0** | 100% | 100% | **1.000** |
| server（`--reach server`） | 925 | 88 | **0** | 100% | 91.3% | **0.955** |

27 条控制例 **0 findings**。server 的 88 条 FN 中，主体是 query 能力缺口；
body/header/path 约 35 条是官方 runner 只给 URL 的投递契约形状。4 条 100s wrapper
超时单独复跑 10–12s 完成并命中，补齐口径 **929 / 84 / 0（R 91.7% / F1 0.957）**。

**同 scorer 三工具对跑（Phase 342，2026-10-30）**：同一官方 XSSMaze v0.3.0 靶 + 官方
runner，三工具逐例对跑——XSSentinel **TP944 / FN69 / FP0**（P 1.000 / R 0.932 /
F1 **0.965**，5741s）、dalfox 757/256/4（F1 0.853，4072s）、nuclei 731/282/4
（F1 0.836，406s）；控制例 FP 我方 0、两竞品各 4（均为 CSP/nonce 防护页）。
**口径限定**：dalfox 臂是 Go 冻结分支 v2.13.0，现行 Rust v3 未对跑（本机取不到其
release 资产）；其 chromedp headless 层在本机不稳而 `--skip-headless`（该层贡献已
另行抽样量化）；我方记分卡复用 p341（两树检测面零提交差）。速度维度 nuclei 仍快
一个量级。工具版本、逐项 deviation 与逐例数据见
[`benchmark/results/phase342_xssmaze/`](benchmark/results/phase342_xssmaze/p342_meta.json)。

### 引用限定（2026-11-08 复核）

[`external_validity_20261108.md`](benchmark/results/external_validity_20261108.md)
把散落的跑分按「样本量 / 工具版本 / 口径 / 不可比项」整理成第三方可复核清单。
引用本节任何数字前先读这几条：

- **本轮全量（2026-11-08，未提交 WIP 树，不是已发布 1.4.3 的成绩）**：
  旧 GET-only 口径 TP 975 / FN 38 / FP 0（R 96.2%、F1 0.981，1959.1s）；
  opt-in POST-aware 口径 TP 987 / FN 26 / FP 0（R 97.4%、F1 0.987，2039.6s）。
  **0.987 不是检测能力提升**——POST-only 端点终于拿到 body，两口径不可直接比较，
  且两者都不与上面的 0.965 / 0.957 比较。**官方口径（2026-11-08 定）仍以
  GET-only 为准**，POST-aware 仅作 opt-in 诊断口径，不改写任何历史数字。
- **三个时点（10-24 / 10-30 / 11-08）不能连成进步曲线**：代码树不同（当前 WIP
  未提交）、Phase 364–371 改动混杂、wrapper 超时设置不同（100s / 30s / 90s）、
  本机 loopback 状态不同。
- **dalfox 结果不可外推到现行版本**：对跑的是 Go 冻结分支 v2.13.0，
  Rust v3 从未对跑。
- **自证与第三方证据分开**：194 例矩阵、range3–7、bWAPP 是自建目标 + 自建答案，
  F1=1.0 只证明没写坏，不得与 XSSMaze 的 F1 并列展示为「两个满分」；
  controls FP=0 只说明靶场控制例，不等于生产环境误报率。
- **空白**：Burp Pro / Acunetix / Netsparker 零对跑，OWASP ZAP 全 BLOCKED /
  unavailable，真实授权目标与生产流量零样本；性能多个口径均比 nuclei 慢一个量级。
  这一层不是再加靶场用例能补上的，本项目也不宣称超越商业 XSS 工具。
- **超时伪影**：本机间歇失稳多次造成假 FN / `partial`，每轮都单跑复现定性，
  不得把未复现的偏差当成判定变化。2026-11-08 傍晚起 `wsl.exe` 被安全策略拦，
  Docker 后端起不来，XSSMaze 复测当前无法进行。

### 基准工具链

- `benchmark/run_benchmark_batched.py [out.json] [batch] [port] [sync|async] [max_payloads] [max_transforms] [timeout]`——分批评估、每批落盘、支持中断续跑与失败重试；**Windows 本机跑完整矩阵请用这个入口**（默认预算 6–7 分钟全矩阵，14/12/90 口径 sync 约 12 分钟、async 约 25 分钟）。续跑时预算变了会丢弃旧结果，不静默合并。
- `benchmark/compare_runs.py A.json B.json`——逐用例 diff（聚合分会掩盖"哪些用例移动了"）。
- `benchmark/repro_case.py CASE_ID [port] [sync|async]`——单跑一个用例，打印服务端原始回显 + 判定 + finding 详情；排误报和验证 FN 是否是环境问题都用它。
- `benchmark/req_stats.py` / `benchmark/layer_profile.py`——请求数分布与层开销剖析（本机耗时噪声可达 ±25×，请求数才是稳定度量）。

---

## 扩展指南

- **加 payload**：编辑 `data/payloads.json`，每条含 `context / payload / tags / confidence / note`，引擎自动按上下文选用。
- **加修复建议**：编辑 `data/fix_advice.json`（123+ 条，按 finding type 索引；`fix_advice.py` 是惰性加载器，API 不变）。
- **加检测场景**：编辑自己的场景 JSON（参考 `data/scenarios.example.json`）并 `--scenarios` 传入：按参数名匹配触发多步 HTTP 流（写入→读取→语义确认），`{token}`/`{param}` 占位符自动替换，适配存储型/二级流（Nuclei 风格）。
- **加绕过变形**：在 `core/transform.py` 的 `REGISTRY` 注册新函数即可被审计引擎调用。
- **加 WAF 指纹**：在 `core/waf.py` 的 `_WAF_SIGNATURES` 增加 `(名称, 正则)`。
- **加 sink/source**：扩展 `core/dom.py` 的源/汇列表。
- **加 LLM 供应商**：编辑 `data/llm_providers.json` 的 `providers` 数组（`base_url` + `keys` + `models`，`enabled` 控制开关；`base_url` 带不带 `/chat/completions` 都会归一化）。凭据可用 `XSSENTINEL_LLM_KEY_<PROVIDER_ID>`（逗号分隔）覆盖，池路径用 `XSSENTINEL_LLM_CONFIG` 覆盖。改完**务必用 `--ai-check` 实测一遍**——供应商给的模型名与可用性别照抄（Phase 176 里 4 家有 3 家的名字是错的，1 家账户已被封）。

---

## 已知限制

- 纯静态/语义确认对复杂上下文（嵌套模板、前端框架编译输出）可能漏报或需无头确认补强。
- 无头确认与 DOM 动态执行确认（L6）依赖 Playwright；未安装时自动跳过/优雅降级（DOM 层退化为静态启发式，反射层仍给出语义确认结论）。
- 爬虫为 BFS 轻量级实现（默认深度 2），复杂 SPA / 鉴权流建议配合 `--headless` 或人工提供入口；`--scope` 可把爬取限制在指定路径前缀内。
- 去重按 `(type, URL, param, context)` 合并同源同参的重复命中；DOM 类忽略 query 差异，避免同一页面的 hash/cookie 型 DOM XSS 被报两次。
- 可复现 PoC 对 DOM 类漏洞会用真实执行型 payload（`<img src=x onerror=alert(document.domain)>`）替换内部标记，确保 PoC 页面点开即触发。
- **盲打 XSS（L5）已支持自动确认**：`--oob self` 起本地监听器、`--oob interactsh` 用公共服务器，收到 beacon 即判定为已确认盲打；若超时未收到回调则不报（避免误判）。`interactsh` 模式需要公网可达的 callback 域名与网络连通，离线时优雅降级为"注入但未确认"。
- **存储型 XSS（L4）需要"展示页"**：你必须提供注入接口与其对应的展示/列表接口（如评论提交页 + 评论列表页），框架才会重新拉取确认持久化执行。
- **AI 报告（`--ai-report`）默认关闭**：一旦开启，目标 URL、参数与载荷会发送给 `data/llm_providers.json` 里配置的第三方 LLM 供应商。检测结论不受影响（模型只写叙事章节），但数据出网这件事由操作者决定。REST API（`--serve`）走同一套开关：扫描时 `{"ai_report": true}`，或取报告时 `?ai=1`。
- 这是安全研究/授权测试工具，请勿用于未授权目标。
