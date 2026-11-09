# 真实外部应用靶场：OWASP Juice Shop v20.2.0（2026-11-09，终树 `ba1016c`）

> 本报告只回答"在这一个第三方真实应用上，产品实际做到了什么"。
> **不与 XSSMaze 1013 例并列，不与商业工具比较，不宣称超越任何工具。**
> 全部数字来自本轮自己的运行，产物路径与复现命令一并给出。

## 一、结论先行

在已推送终树 `ba1016c` 上，用**官方 Juice Shop v20.2.0 release**（自包含包，
MD5 与官方一致）作为真实第三方目标，按 `dev/juiceshop_external.py` 的
5 种投递方式扫描：

- **4 / 5 面各命中 1 条 `dom_dynamic` / `high` / `high` /
  `browser-executed` finding**（真实浏览器确认执行，不是静态猜测）；
- **1 面（REST `/rest/products/search?q=`）0 findings** —— 该面 `surfaces`
  已独立测得 `reflects=False`，0 是正确答案，不是漏报；
- **误报 0**：`writes` 基线证明 `/redirect?to=` 只做 HTML 转义、
  `/api/Feedbacks` 入库即被 `sanitize-html` 剥离，扫描在这两个控制面
  均未产出 finding；
- 对照官方答案键 `data/static/challenges.yml` 的 **9 个 XSS 挑战**，
  本轮 5 面只覆盖其中 **2 个**（`localXssChallenge` DOM XSS、
  `reflectedXssChallenge` Reflected XSS）。**其余 7 个本轮根本没有投递，
  既不是 TP 也不是 FN，不计入任何率。**

⇒ 5 是**同一应用的 5 种调用形态**，不是 5 个独立靶、更不是 5 个漏洞。
本轮能支撑的是"真实 SPA 上能独立发现并确认 DOM XSS，且不在明显控制面误报"；
不能支撑任何覆盖率、召回率或跨工具优劣结论。

## 二、环境与证据归属（这轮先修的是环境，不是产品）

| 阻塞 | 处置 |
|---|---|
| XSSMaze 官方靶需要 Docker；`wsl.exe` 被本机安全策略拉黑（明确要求不得重试或找等价绕过），`docker version` 连不上 daemon | 本轮**放弃** XSSMaze 复测；需要仓库归属者到安全中心解除黑名单后才能跑 |
| `dev/_juiceshop/app/juice-shop_20.2.0/` 只剩 `data/` + `logs/`，`build/app.js` 与 `node_modules/` 已被 2026-10 工作区清空删除 | 经 `api.github.com`（直连）查 v20.2.0 release 资产，取 `juice-shop-20.2.0_node22_win32_x64.zip`；经 `ghfast.top` 镜像下载 **126,207,633 B / 12m37s**；官方 `.md5` = 实际 `md5sum` = `1191bb6ed1ab696507bb0b50b27bb7a5`；解压 **44,140 文件 / 36.4s**，`build/app.js` 就位、`node_modules` 848 包 |
| 运行时代理会污染 loopback 静态资源（driver docstring 的已知坑） | 全程 `NO_PROXY=127.0.0.1,localhost` + `no_proxy` 小写形式 |
| 解释器 | `.venv/Scripts/python.exe`（3.12.10）；Node `v22.22.2`；端口 `18900` |

`dev/_*` 已被 `.gitignore` 忽略，恢复的 44k 文件**不进版本库**。
`dev/_js_out/` 里还混有历史产物（端口 18901 的 `findings_p287_*`、
`findings_oneshot_d1.json` 等），**不属于本轮**；本轮产物按 21:44–21:49
时间戳界定为下列 5 个文件。

## 三、逐面结果（本轮，2026-11-09 21:43:19–21:49:41，6m22s）

| 面 | 命令要点 | findings | requests | 耗时 | 命中 URL |
|---|---|---|---|---|---|
| `oneshot` | `-u BASE -c --crawl-depth 2 --headless` | **1** | 249 | 48.5s | `/#/track-result?id=xss` |
| `discover` | `-u BASE -c --discover --headless` | **1** | 3609 | 318.5s | `/#/track-result?id=xss` |
| `api-surface` | `-u BASE/rest/products/search?q=apple --headless` | **0** | 25 | 1.6s | — |
| `dom-route` | `-u BASE/#/search?q=apple --headless` | **1** | 9 | 6.4s | `/#/search?q=apple` |
| `dom-route-result` | `-u BASE/#/search-result?q=apple --headless` | **1** | 9 | 6.4s | `/#/search-result?q=apple` |

5 次全部 `exit=0`、`requests_failed=0`。4 条 finding 的公共形状：
`type=dom_dynamic`、`severity=high`、`confidence=high`、
`evidence_class=browser-executed`，注入点为 `q@hash` / `id@hash`。
产物：`dev/_js_out/findings_{oneshot,discover,api-surface,dom-route,dom-route-result}.json`，
原始 stdout 落在 `%TEMP%/juice_scan_20261109.log`。

`discover` 用了 3609 次请求 / 318.5s 才拿到与 `oneshot`（249 次 / 48.5s）
相同的 1 条 finding —— **这是成本事实，不是能力差异**，写在这里防止把
"请求更多"读成"检得更多"。

## 四、官方答案键核对与归因基线

`surfaces` / `writes` 两条独立测量（`dev/juiceshop_external.py`）：

```
/redirect?to=<iframe...>    status=406  escaped_iframe=True  marker=True   → 只转义，不可执行
ssti {{7*7}}                rendered_49=True  verbatim=True  coincidence=True → 行号巧合
POST /api/Feedbacks         status=201  sanitizer_stripped=True  raw_iframe_stored=False
GET  /api/Users             status=401  needs_auth=True
/rest/products/search?q=    reflects=False  iframe=False
```

`data/static/challenges.yml` 中 9 个 `category: XSS` 挑战：

| key | 名称 | 本轮 |
|---|---|---|
| `localXssChallenge` | DOM XSS | **覆盖并确认**（`/#/search?q=`、`/#/search-result?q=`） |
| `reflectedXssChallenge` | Reflected XSS | **覆盖并确认**（`/#/track-result?id=`） |
| `restfulXssChallenge` | API-only XSS | 未投递（需特定 API 载荷） |
| `usernameXssChallenge` | CSP Bypass | 未投递（需认证态） |
| `persistedXssUserChallenge` | Client-side XSS Protection | 未投递（需认证态） |
| `persistedXssFeedbackChallenge` | Server-side XSS Protection | 未投递（本版 sanitizer 已剥离，见 `writes`） |
| `httpHeaderXssChallenge` | HTTP-Header XSS | 未投递（需 header 注入） |
| `videoXssChallenge` | Video XSS | 未投递（需构造视频文件） |
| `xssBonusChallenge` | Bonus Payload | 未投递（需特定 `<iframe src="javascript:...">`） |

**未覆盖的 7 个一个都不算 FN**：本轮矩阵没有向它们投递任何载荷。
把它们计入分母，或把"4 面命中 / 5 面"换算成 80%，都是错的。

## 五、能支撑 / 不能支撑

**能支撑**：在一个真实的第三方 Angular SPA + Express + SQLite 应用上，
产品用"只给一个 URL"的方式（`oneshot`）独立发现并**经真实浏览器确认**
了 DOM XSS；在明确不反射 / 被转义 / 被净化的控制面上没有误报。

**不能支撑**：
- 任何召回率、覆盖率或 F1（分母不是 9，也不是 5 个独立靶）；
- 与 Burp Pro / Acunetix / Netsparker / ZAP 的比较（本轮零对跑，
  商业工具与本机的已知环境限制见 `external_validity_20261108.md`）；
- 与 XSSMaze 1013 例（F1 0.981）或 194 自编矩阵并列展示；
- "超越商业工具"或"生产环境表现"的任何结论；
- 性能结论（本机 loopback 与浏览器调度会显著影响墙钟）。

**明确未验证**：跨工具同台对跑。dalfox v2.13.0 / nuclei v3.9.0 都在本机
`~/go/bin`，但二者输出格式与"什么算 finding"口径不同，且 hash 路由不是
它们的设计输入面；仓促跑出的数字会变成误导性对比。要做需先定统一判定
口径与版本清单，单列一轮。

## 六、复现

```bash
# 1) 目标（一次性；dev/_* 不进版本库）
#    api.github.com 查 release assets -> ghfast.top 下
#    juice-shop-20.2.0_node22_win32_x64.zip，校验 .md5，解压到
#    dev/_juiceshop/app/juice-shop_20.2.0/
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
.venv/Scripts/python.exe dev/juiceshop_external.py serve      # 常驻，另开终端
.venv/Scripts/python.exe dev/juiceshop_external.py status     # healthy=True
.venv/Scripts/python.exe dev/juiceshop_external.py surfaces
.venv/Scripts/python.exe dev/juiceshop_external.py writes
.venv/Scripts/python.exe dev/juiceshop_external.py scan
```

`start` 子命令是"启动→健康检查→即停"的探针，**不会常驻**；要跑扫描
必须用 `serve`。
