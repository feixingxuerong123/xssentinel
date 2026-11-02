# nuclei / nuclei-templates 外部事实调研(供 XSSentinel 对比分析)

调研日期:2026-11-01。**所有数字均来自本次实际打开的页面/接口**,禁止引用记忆;每条标注来源 URL 与页面快照期证据。

方法说明:抓取通道对 GitHub 存在多层缓存,不同 URL 命中不同日期的快照。本报告对关键数字交叉验证后取**最新快照**的值,旧快照数字在 §6 留存轨迹;无法定年的快照单独标注。

---

## 1. projectdiscovery/nuclei(引擎仓库)

| 事实 | 数值 | 来源 | 快照期证据 |
|---|---|---|---|
| Stars | **32,303** | https://api.github.com/repos/projectdiscovery/nuclei | 响应内 `updated_at=pushed_at=2026-10-25`,快照≈10-25;组织页 pinned 显示 32.2k,两源一致 |
| Forks | 3,941 | 同上 | 同上 |
| Open issues+PRs | 92 | 同上 | 同上 |
| 最新 release | **v3.11.1,2026-08-08 发布** | https://api.github.com/repos/projectdiscovery/nuclei/releases/latest(`published_at=2026-08-08`);https://github.com/projectdiscovery/nuclei/releases 首条同为 v3.11.1 | release 后仓库仍在推送(`pushed_at=2026-10-25`) |
| License | MIT | API `license` 字段 | — |
| 语言 / 创建时间 / 默认分支 | Go / 2020-04-03 / dev | API | — |
| 订阅者(watch) | 279 | API `subscribers_count` | — |

- **维护主体**:`projectdiscovery`(GitHub Organization,域名 projectdiscovery.io 已验证)。组织 README 原文:"ProjectDiscovery is an open source powered security company. We specialize in detecting new, exploitable vulnerabilities and misconfigurations…"。组织 12.2k followers,团队成员(profiles)含 ehsandeep、Mzack9999、princechaddha、dwisiswant0、Ice3man543、DhiyaneshGeek 等。来源:https://github.com/projectdiscovery(页脚 © 2026,条目"Updated Oct 20, 2026")。**公司背书:是。**
- **贡献者数**:shields.io 实时徽章读数 **284**(第三方徽章服务,读 GitHub 数据,可能有数小时缓存):https://img.shields.io/github/contributors/projectdiscovery/nuclei.json → `{"label":"contributors","message":"284"}`。GitHub 官方 graphs/contributors 页为前端渲染,本次无法读取,**官方精确计数待证**(见 §7)。佐证规模:release notes 每版列 New Contributors(v3.11.1 列 6 名,v3.8.0 列 17 名)。

## 2. 定位与能力(仅页面原文)

- 定位(README):"Nuclei is a modern, high-performance vulnerability scanner that leverages simple YAML-based templates. It empowers you to design custom vulnerability detection scenarios that mimic real-world conditions, leading to zero false positives."
- 官方描述(API description):"…find vulnerabilities in your applications, APIs, networks, DNS, and cloud configurations." ——**通用漏洞扫描器定位,无 XSS 专精表述**。
- 协议/模板类型(README `-pt`/`-ept` 标志枚举,共 11 类):**dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript**;README 另文:"Supports multiple protocols like TCP, DNS, HTTP, SSL, WHOIS, JavaScript, Code and more."
- **Headless**(https://docs.projectdiscovery.io/templates/protocols/headless):"Nuclei supports automation of a browser with simple DSL. Headless browser engine can be fully customized and user actions can be scripted allowing complete control over the browser."
  - 动作清单(文档逐条列出):navigate, script, click, rightclick, text, screenshot, time, select, files, waitfcp, waitfmp, waitdom, waitload, waitidle, waitstable, waitdialog, getresource, extract, setmethod, addheader, setheader, deleteheader, setbody, waitevent, keyboard, debug, sleep;选择器支持 XPath/Regex/CSS 等。
  - XSS 相关原文:waitdialog——"useful for detecting triggered XSS payloads with a high level of accuracy and a low rate of false positives";script 的 hook——"function hooking such as DOM XSS Detection and Javascript-Injection based testing techniques"。
- **Workflow / 条件模板**(https://docs.projectdiscovery.io/templates/workflows/overview):分 Generic 与 Conditional 两类;条件可按「基础模板匹配」或「matcher 名」触发,支持"as many and as nested checks…as needed"的多级链;执行环境共享:"Nuclei engine supports transparent workflow cookiejar and key-value sharing across templates parts of a same workflow"(前一模板的 extractor 值可在后续模板按名引用)。
- **Fuzz / DAST**(https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview):"Nuclei supports fuzzing of HTTP requests based on rules defined in the fuzzing section… This allows creating templates for generic Web Application vulnerabilities like SQLi, SSRF, CMDi, etc without any information of the target like a classic web fuzzer. We call this concept as **Fuzzing for Unknown Vulnerabilities**."
  - part = query(默认)/ path / header / cookie / body / request;type = replace/prefix/postfix/infix/replace-regex;mode = multiple(默认)/ single;支持 keys/keys-regex/values 过滤;`time_delay` analyzer(线性回归,文档明言"ported from ZAP");**文档以"An example sample template for fuzzing XSS vulnerabilities"收尾**。
- 引擎侧 XSS 相关 release 要点(https://github.com/projectdiscovery/nuclei/releases):
  - v3.8.0:"Fuzz: Add XSS reflection context analyzer by @ZachL111 (#7164)"
  - v3.11.0 破坏性变更:"custom templates that use the `javascript:` protocol must be digitally signed before Nuclei will load or execute them"(官方模板预签名)
  - v3.10.0:一组 DAST/fuzz 安全加固(模板渲染边界、code 模板签名校验等)
- 其他能力(README):Interactsh OOB;LLM 语义 matcher(`-llm`);AI 生成模板(`-ai`);输出 JSON/JSONL/Markdown/SARIF/PDF;payload 组合模式 batteringram/pitchfork/clusterbomb;安装要求 `go >= 1.27.3`,`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`。

## 3. projectdiscovery/nuclei-templates(模板仓库)

| 事实 | 数值 | 来源 | 快照期证据 |
|---|---|---|---|
| Stars | **13,132**(Forks 3,698) | https://github.com/projectdiscovery(Repositories 列表) | 该快照条目"Updated Oct 20, 2026"、页脚 © 2026;轨迹见 §6 |
| 最新 release | **v10.5.1,2026-10-23** | https://github.com/projectdiscovery/nuclei-templates/releases | "princechaddha released this 23 Oct 11:19",标 Latest;GitHub 省略年份=当年,且该列表含 v10.4.4(API 证实 2026-05-28)→ 推断为 2026-10-23 |
| License | MIT | API `license` 字段 | — |
| 创建时间 | 2020-04-04 | API | — |

- **模板规模**(仓库主页,本次抓取;页面未标注统计 as-of 日期):"**873 directories, 11997 files**"。README 统计表(前 10):directory——http 9,281 / cloud 659 / file 436 / network 259 / code 251 / **dast 240** / workflows 205 / javascript 92 / ssl 38 / dns 23;tag——xss **1,269**、cve 3,587、vuln 6,468、vkev 1,394;severity——info 4,353 / high 2,552 / medium 2,457 / critical 1,555。来源:https://github.com/projectdiscovery/nuclei-templates
- **KEV 覆盖**(同页):CISA KEV 454 / VulnCheck KEV 1,449 / 双源 407 / **去重合计 1,496**。
- **社区贡献流程**(README 原文):"We hope that you also contribute by sending templates via **pull requests** or Github issues to grow the list.";另有 GitHub Discussions 与 Discord 社区。每版 release notes 公布 `First-time contributions`(v10.5.1=11、v10.5.0=11、v10.4.4=20)与贡献者名单(v10.5.1:"alex, het, and 34 other contributors" = **36 人/单版**)。
- **更新频率**:已知锚点 v10.4.4=2026-05-28(API)、v10.5.0=2026-10-05、v10.5.1=2026-10-23(releases 页);5–10 月间 7 个版本 ≈ **3 周一版**;每版新增模板 68(v10.5.1)~ 295(v10.5.0)个。commits 为每日机器人任务(签名、checksum、新增清单、EPSS 更新)+ 社区 PR 合并(2024-12 与 2025-12 两次快照均见逐日提交;组织页显示 2026-10-20 仍更新)。
- **头部模板作者**(README 统计,按模板数):dhiyaneshdk 1,894 / daffainfo 905 / princechaddha 854 / dwisiswant0 805 / ritikchaddha 678 / pussycat0x 675 / pikpikcu 353 / pdteam 314 / pdresearch 275 / iamnoooob 263。
- **贡献者数**:shields.io 徽章读数 **362**(第三方):https://img.shields.io/github/contributors/projectdiscovery/nuclei-templates.json;官方精确计数待证。
- dast/ 目录结构:含 `cves/` 与 `vulnerabilities/` 两个子目录(https://github.com/projectdiscovery/nuclei-templates/tree/main/dast,该快照页脚 © 2024,偏旧);dast fuzz 模板含 reflected-xss、windows-lfi-fuzz 等(GitHub issue #5533 用户提及,线索级,非官方文档)。

## 4. 生态集成与许可

- **官方 GitHub Action**:https://github.com/projectdiscovery/nuclei-action ——"makes it easy to orchestrate Nuclei with GitHub Action… make it part of your secure software development life cycle"。
  - v3.0.0+:Node.js v24,CLI-first 输入(version / install-only / args / config / config-path / cache / token),输出 stdout/stderr;`cache` 可缓存 nuclei 配置、模板与浏览器。
  - v2.x:"deprecated and unsupported after **March 1, 2026**"。
  - 官方示例:SARIF 导出 + `github/codeql-action/upload-sarif@v3` 接入 GitHub code scanning;支持 GitHub issue 上报配置。
  - License:MIT。
- **CI/CD**(引擎 README):"Integrate into CI/CD pipelines for vulnerability detection and regression testing";"Integrate with Jira, Splunk, GitHub, Elastic, GitLab."
- **许可**:nuclei MIT / nuclei-templates MIT / nuclei-action MIT(API license 字段与组织页一致);OSS CLI 完全免费。
- **开源与商业边界**(引擎 README + 组织页):OSS CLI 免费自用;ProjectDiscovery Cloud Platform(PDCP)提供**免费层**("a free cloud tier that comes with generous monthly free limits");**Pro / Enterprise 为付费云服务**("cloud-hosted service built on top of Nuclei OSS",宣传 50x faster scans、SAML SSO、SOC 2、云厂商集成等);组织页:"Get started for free and upgrade if needed to enable cloud scanning and other features."
- README 警示:"This project is primarily built to be used as a standalone CLI tool. Running nuclei as a service may pose security risks."

## 5. 「专用 XSS 深度检测」的官方边界(只引官方明示,不替它推断)

官方页面明示的 XSS 相关能力,穷举如下:
1. **模板库**:tag `xss` 1,269 个模板;dast 目录 240 个(其中 vulnerabilities/ 下含反射型 XSS fuzz 模板——树页结构为官方页面,具体文件名为 issue 线索)。
2. **Fuzz**:fuzzing 文档以 XSS fuzz 模板为收尾示例;v3.8.0 release note:"Add XSS reflection context analyzer"。
3. **Headless**:waitdialog("detecting triggered XSS payloads with a high level of accuracy and a low rate of false positives",官方自称)与 script hook("DOM XSS Detection and Javascript-Injection based testing techniques")。

边界表述:官方定位语句(README/API description)覆盖 applications、APIs、networks、DNS、cloud configurations,**未出现「XSS 专用 / 深度 XSS 检测」定位**。本次打开的官方页面(两仓库 README、releases、docs 的 headless/workflow/fuzzing 页、nuclei-action)未出现 CSP nonce 泄露利用链、存储型 XSS 专项流水线、双引擎(同步/异步)等表述。**「未见于本次打开的页面」≠「不具备该能力」**,此处不做反向推断。

## 6. 快照轨迹(缓存不一致的原始记录,保证可复核)

- nuclei-templates stars:9.5k(HTML commits 页,页脚 © 2024,commits 至 2024-12-16)→ 11.7k(commits/main 页,页脚 © 2025,commits 至 2025-12-14)→ 12,475(API,`updated_at=2026-06-05`)→ **13,132(组织页,条目 Updated Oct 20, 2026)**。取最新快照。
- nuclei stars:32,303(API,快照 2026-10-25)≈ 32.2k(组织页)——两源一致,直接采用。
- templates 最新 release:API `/releases/latest` 返回 v10.4.4(2026-05-28)为旧缓存;releases HTML 页显示 v10.5.1(10-23)。取 v10.5.1。
- nuclei 引擎 release:API `/releases/latest` 与 releases HTML 页一致(v3.11.1,2026-08-08)。

## 7. 待证项(值得跟进)

1. 两仓库的**官方贡献者总数**:GitHub graphs/contributors 为前端渲染,API contributors 列表端点本次不可用;已有第三方读数(284 / 362)与 release notes 佐证。建议:登录态打开 graphs/contributors,或带认证调 API 读 Link 头分页总数。
2. 模板统计(11,997 files 等)的官方 as-of 日期:README 未标注统计时点;建议用 `nuclei -tl` 或官方 stats JSON 核对当前值。
3. v10.4.5–v10.4.9 的确切发布日期(补全 release 节奏曲线)。
4. dast/vulnerabilities/ 下当前文件清单(reflected-xss 等 fuzz 模板的权威名单)——树页快照偏旧,建议直接 `git ls-tree` 或 GitHub API contents。

## 8. 来源清单(本次实际打开)

- https://github.com/projectdiscovery/nuclei(README)
- https://api.github.com/repos/projectdiscovery/nuclei 及 `/releases/latest`、`/releases`
- https://github.com/projectdiscovery/nuclei/releases
- https://github.com/projectdiscovery/nuclei-templates(README)
- https://api.github.com/repos/projectdiscovery/nuclei-templates 及 `/releases/latest`
- https://github.com/projectdiscovery/nuclei-templates/releases
- https://github.com/projectdiscovery/nuclei-templates/commits/main(2025-12 快照)、`/commits/main/`(2024-12 快照)
- https://github.com/projectdiscovery/nuclei-templates/tree/main/dast(2024 快照)
- https://github.com/projectdiscovery(组织页,2026-10 快照)
- https://github.com/projectdiscovery/nuclei/contributors(前端渲染,无数值)
- https://docs.projectdiscovery.io/templates/protocols/headless
- https://docs.projectdiscovery.io/templates/workflows/overview
- https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview
- https://github.com/projectdiscovery/nuclei-action
- https://img.shields.io/github/contributors/projectdiscovery/nuclei.json(284)
- https://img.shields.io/github/contributors/projectdiscovery/nuclei-templates.json(362)
