# XSS 扫描器竞品对照(2026-10 复核)

> 目的:回答两个不同的问题——
> **(A) 能力对照**:行业"做得好"的工具都具备什么?
> **(B) 同靶实测**:在同一批目标上,别人扫得出多少?
> 本文是 (A)。(B) 见 README「外部参照:同类开源扫描器同靶跑分」,那里有 60 例对跑数据。
>
> 方法:`web_fetch` 直抓 GitHub REST API / raw README / 官方文档站。
> **凡未能在页面上直接读到的,一律标注「未查证」,不做推测。**

---

## 0. 先纠三个前提错误(引用本文前请勿沿用旧写法)

调研请求里给的三个仓库路径,**两个是 404,一个不存在**:

| 常见误写 | 实际情况 | 证据 |
|---|---|---|
| `Sw33tLie/XsSer` | **404**。真实项目是 [`epsylon/xsser`](https://github.com/epsylon/xsser)(XSSer,Kali 官方收录) | [api/repos/Sw33tLie/XsSer → 404](https://api.github.com/repos/Sw33tLie/XsSer) |
| `JAEGER Security Research/gospider` | **404**。已迁至 [`jaeles-project/gospider`](https://github.com/jaeles-project/gospider) | [api/repos/jaeger-security-research/gospider → 404](https://api.github.com/repos/jaeger-security-research/gospider) |
| `kheper`(XSS 扫描器) | **GitHub 上不存在**。`q=kheper+xss` → `total_count: 0` | [api/search?q=kheper+xss → 0](https://api.github.com/search/repositories?q=kheper+xss) |

**并且:DalFox v3 已从 Go 完整重写为 Rust**,v2.x 的 Go 版冻结在 `v2` 分支只收安全 backport。
所以"DalFox — Go"在最新版已经不成立。
来源:[README "V2" 段](https://raw.githubusercontent.com/hahwul/dalfox/main/README.md)、[v3.2.4 release](https://github.com/hahwul/dalfox/releases/tag/v3.2.4)

---

## 1. 活跃度分层(2026-10 实测)

| 工具 | 语言 | 最新版本 | 最近发布 | 状态 |
|---|---|---|---|---|
| **[DalFox](https://github.com/hahwul/dalfox)** | **Rust**(v3)/ Go(v2 冻结) | **v3.2.4** | 2026-10-07 | 🔥 极活跃,近乎周更 |
| **[nuclei](https://github.com/projectdiscovery/nuclei)** | Go | v3.11.1 | 2026-08-08 | 🔥 活跃 |
| **[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)** | YAML | v10.5.0 | 2026-10-05 | 🔥 活跃 |
| **[XSSer](https://github.com/epsylon/xsser)** | Python | xsser-v1.9 | 2026-07-09 | ✅ 活跃(最后 push 2026-09-05) |
| **[XSStrike](https://github.com/s0md3v/XSStrike)** | Python | 3.1.6 | 2025-03-17 | ⚠️ 半停更(最后 push 2025-04,96 open issues) |
| **[GoSpider](https://github.com/jaeles-project/gospider)** | Go | v1.1.6(tag) | 最后 push **2024-04-21** | ❌ 事实停更(56 open issues) |
| **[XSLeaks](https://github.com/xsleaks/xsleaks)** | — | 无 release | 最后 push 2024-03-19 | ❌ 停更 |

**读法**:这个赛道只有 DalFox 和 nuclei 还在周更级维护。XSStrike 15k star 却已一年半无更新,
GoSpider / XSLeaks 早已停更。**"同类竞品"实际只有两个活的**。

---

## 2. 能力矩阵

| 维度 | DalFox v3.2.4 | XSSer 1.9 | XSStrike 3.1.6 | nuclei(1269 个 xss 模板) | GoSpider | DOMDig / Burp DOM Scanner | DOM Invader(参照) |
|---|---|---|---|---|---|---|---|
| **HTML 正文/属性/URL/JS/CSS** | ✅ 全覆盖(context-aware) | ✅ | ✅ 四手写 parser | ✅ 模板级 | ❌ 只爬不验 | ✅ | ✅ |
| **mXSS** | ✅ 内置 | 部分(1500+ vectors) | 未查证 | 少数模板 | ❌ | 未查证 | ✅ 强项 |
| **DOM 型** | ✅ **静态 AST**,不做浏览器执行 | ✅ Selenium + `--Dom` | ✅ | ⚠️ 主要靠模板 | ❌ | ✅ **真 Chromium 执行** | ✅ |
| **Stored / SXSS** | ✅ `--sxss`,含 snapshot + 重试 | ✅ | 部分 | ✅ 模板 | ❌ | ✅ | ❌ 手动 |
| **盲打 / OOB** | ✅ `-b` + `--blind-oob` | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ Collaborator |
| **二阶 / 延迟** | ✅ interactsh 轮询 | 未查证 | ❌ | ❌ | ❌ | ✅ | ❌ 手动 |
| **CSP nonce 泄露链** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **headless 浏览器验证** | ❌ **无**。文档明说"static parse of a real response, **not browser execution**" | ✅ Firefox/geckodriver | ❌ | ❌(部分 `-headless`) | ❌ | ✅ Chromium | ✅ |
| **参数发现** | ✅ query/header/cookie/path/form/fragment + 字典挖掘 + `<input>` + **GraphQL/XML/base64/JWT 自动拆解** | ✅ crawler + dorking | ✅ Arjun + Photon | ❌ 靠 crawler 喂 | ✅ 爬虫 + sitemap + JS + Wayback | ✅ DOM 内注入 | ✅ Proxy 历史 |
| **认证** | ✅ header/cookie + `session_check` 掉线检测 | ✅ cookie/UA/Tor/客户端证书 | ✅ | ✅ | ✅ cookie/`-H`/Burp 导入 | ✅ http auth + 脚本登录 | ✅ 继承 Burp 会话 |
| **并发/限速** | ✅ `--workers` + 精确 `--rate-limit`;**stored 强制串行** | 未查证 | ✅ | ✅ 高并发 | ✅ 多层 | 受限 | 人工 |
| **误报控制** | ✅ **三轴**(type/detection_method/severity)+ confidence + safe-context 过滤 + `--min-confidence` | ✅ reverse-check | ✅ context analysis | ❌ 模板级 | ❌ | ✅ `confirmed` 字段 | ✅ 真实执行 |
| **报告格式** | ✅ plain/JSON/JSONL/MD/SARIF/TOML + `--baseline` 增量 | ✅ PDF/XML/JSON | 未查证 | ✅ 原生四格式 | ✅ JSON | ✅ | ✅ |
| **MCP / AI** | ✅ **`dalfox mcp`** stdio MCP(6 工具)+ REST API + Agent Skill | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 商业生态 |
| **客观跑分** | ✅ **XSSMaze 97.8%** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## 3. 行业能力天花板:三档

### 第一档 —— 事实门槛(达不到就出局)

1. **上下文感知的 payload 生成**,不是"注入后看回显"。必须区分 HTML 正文/属性/URL/JS/CSS 并各自定制。
2. **三轴置信度建模**:`能不能用` / `怎么发现的` / `多严重` 解耦。
   ⚠️ 连 DalFox 官方文档都承认 severity 目前只是 tier 的复述、不携带独立信息——**头部也没解决"独立影响面评级"**。
3. **机器可读 + CI 门禁**:SARIF + 稳定 fingerprint + 三态退出码(0 无 / 1 有发现 / 2 错误)。
4. **基线增量**:按漏洞指纹(而非 payload)去重,只报新增。**这条竞品几乎都没做**,DalFox 也刚加。
5. **会话存活检测**:`session_check` 掉线标 `SESSION_LOST`,而不是伪装成 clean。
6. **不完整扫描必须可辨识**:`incomplete: true` + `target_summary[].status`,让 "0 findings" ≠ "干净"。

### 第二档 —— 明显拉开差距

7. **多位置参数发现** + **噪声防护**(整页回显型站点会让扫描爆炸)。
8. **三明治 marker 探针**(OPEN+INNER+CLOSE):能识别 PrefixOnly/SuffixOnly/InnerOnly,覆盖前后缀剥离型过滤器。单 token 探针会全部漏报。
9. **WAF 识别 + 绕过闭环**:指纹带置信度、报告里记录绕行期间发多少/被挡多少。
10. **结构化请求体注入**:GraphQL `variables.*`、XML/SOAP、multipart,且替换后请求本身仍合法。
11. **OpenAPI / Postman / HAR 导入**:直接消费 API 规格而不是爬。
12. **AI 集成(MCP)**:**开源 XSS 扫描器里目前只有 DalFox 做了完整 MCP**。

### 第三档 —— 头部也只做到一半(**这里就是机会**)

13. **真浏览器确认**:只有 XSSer 和 DOMDig/DOM Invader 有。**DalFox 没有**——
    它靠 AST 静态解析证明"payload 到了可执行位置",并明确声明这不等于浏览器执行。
14. **可复现的客观跑分**:只有 XSSMaze 一套,且只有 DalFox 自报了分。
    **整个领域没有中立的横向评测**——15k star 的 XSStrike 连自己的 benchmark 都没有。
15. **CSP nonce 泄露利用链**:**全部竞品零覆盖**。
16. **SPA / WebSocket / postMessage 面**:命令行工具基本没有。

---

## 4. XSSentinel 的差异化位置(按稀缺度 × 价值排序)

| # | 能力 | 稀缺度 | 说明 |
|---|---|---|---|
| 1 | **CSP nonce 泄露自动利用链** | ★★★★★ | 所有竞品 README/docs 均未提及。竞品天花板只到"发现注入点"和"绕过 WAF",没人做"发现 CSP 缺陷 → 提取 nonce → 构造穿透 CSP 的完整链" |
| 2 | **中立横向 benchmark** | ★★★★★ | XSSMaze 只能测 DalFox。本仓 `benchmark/` + range3/4 可同时评多个工具,本身是社区级壁垒 |
| 3 | **两段式流水线**(静态收敛 → 浏览器确认) | ★★★★ | 市场现状是**二选一**:DalFox 快速静态(97.8%)vs XSSer/DOMDig 有浏览器但慢。**中间地带无人占据** |
| 4 | **场景 DSL(Nuclei 风格多步流)** | ★★★★ | 竞品全是"单请求→看回显"的命令式流程。本仓 DSL 是纯 XSS 领域专用、可扩展 |
| 5 | **MCP server** | ★★★ | DalFox 已做并公开文档,但开源 XSS 扫描器里仍是 1/1。后发者需差异化:暴露 DSL 场景执行 / benchmark / 修复建议这些**别人没有的数据资产** |
| 6 | **修复建议引擎数据化** | ★★★ | `fix_advice.py` "改 JSON 语料而非改引擎" + 按 context 给出可执行建议。**全部竞品只报漏洞,不给修复路径** |
| 7 | **双流水线(sync + async)** | ★★★ | 竞品都是单一并发模型 |
| 8 | **自托管 OOB**(非 interactsh) | ★★★ | 主流 `-b interactsh` 有外部依赖;本仓可自托管回连,去掉第三方服务依赖 |

---

## 5. 结论与风险提示

1. **"最快 + 最广 + 最准"这条路已被 Rust 版 DalFox 占住**:97.8% 跑分、6 种输出、MCP、REST、
   Agent Skill、WAF 绕过闭环全齐。**硬拼覆盖度胜算不高。**
2. **可打的空档是三条**:
   - (a) 浏览器执行确认(静态派 vs 浏览器派之间的中间地带);
   - (b) 二阶/AUTH/多步时序(**DalFox 的 stored 是强制串行的**,`--workers` 明确无效);
   - (c) 修复建议 + 编排(MCP + DSL + fix_advice 组合是独一份的)。
3. **报告层已不是差异化**:六格式 + SARIF + 基线门禁已是 DalFox 标配,本仓**已持平,不必再投入**。
4. **引用本文时务必用修正后的仓库路径**,并注明 DalFox 已是 Rust 而非 Go。

---

## 6. 未查证清单(诚实边界)

- DalFox / nuclei / nuclei-templates 的 star 数(未逐个取 repo API)
- XSSer 的并发参数与 `--crawl` 具体行为
- XSStrike 是否输出 JSON(仅见终端文本)
- DOMDig / burp-dom-scanner 的 star 数与最近提交时间
- Burp DOM Invader 当前版本号与完整 attack type 清单(文档目录树抓到章节名,正文页多次 404)
- nuclei XSS 模板具体目录路径(`http/xss` 与 `xss` 均 404;code search 需鉴权返回 401,仅确认 `xss` tag 共 **1269** 个模板)
- XSSer 官网是否有非 GitHub 的 issue 渠道

---

### 主要来源

- DalFox:[README](https://raw.githubusercontent.com/hahwul/dalfox/main/README.md) · [Parameters](https://dalfox.hahwul.com/guide/parameters/) · [Detection Model](https://dalfox.hahwul.com/guide/detection-model/) · [Output](https://dalfox.hahwul.com/guide/output/) · [XSSMaze](https://dalfox.hahwul.com/reference/xssmaze/) · [MCP](https://dalfox.hahwul.com/integrations/mcp/)
- XSSer:[README](https://raw.githubusercontent.com/epsylon/xsser/master/README.md)
- XSStrike:[README](https://raw.githubusercontent.com/s0md3v/XSStrike/master/README.md)
- GoSpider:[README](https://raw.githubusercontent.com/jaeles-project/gospider/master/README.md)
- nuclei-templates:[README(1269 xss tag)](https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/README.md)
- DOMDig:[README](https://raw.githubusercontent.com/fcavallarin/domdig/master/README.md) · [burp-dom-scanner](https://raw.githubusercontent.com/fcavallarin/burp-dom-scanner/main/README.md)
- DOM Invader:[PortSwigger 文档目录](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)