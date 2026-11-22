# DVWA × 本地 glm-5.3-flash 实测记录（第三轮，2026-11-19c，网关实况校正版）

本轮起因：用户提供了两套本地 LLM 网关配置，要求「优先 dv4.1 flash 开始测试 dvwa 靶场」。
**先实测网关可达性再选模型**，结论：`dv4.1 flash` 两个端点都拿不到，经用户确认后改用
已验证可用的 `glm-5.3-flash`。所有数字来自本轮真实运行（2026-11-19 23:07–23:16 GMT+8），
未沿用旧快照。产物带后缀 `20261119c`，不覆写今早 `20261119b` 证据。

## 1. 网关实测（本轮新增的结论，先于扫描）

| 端点 | 实测结果 | 判定 |
|---|---|---|
| `http://127.0.0.1:18080/v1/models` | 列出 `glm-5.3` / `glm-5.3-flash` | 可用 |
| 18080 转发 `dv4.1-flash` / `deepseek-v4.1-flash` / `deepseek-v4.1-flash-free` | 全部 `{"code":3006,"msg":"model not allowed"}` | **不可用** |
| `http://127.0.0.1:8326/v1/chat/completions`（dsh channel gateway） | HTTP 000，无监听；全机无 dsh/cordis 进程 | **不可用** |
| dsh 配置实况 | `~/.dsh/our-free-model/settings.json`：`forward.enabled=false`、`chanGateway.relay.enabled=false`；`dv4.1 flash` 只在模型池清单 `state.json`/catalog 里登记，网关未启动 | 需起 dsh harness 才可达 |

`dv4.1 flash` 的 key（`ap0Q...`）确实等于 `~/.dsh/openai-gateway/api-key`，配置本身不假，
但网关进程没跑 ⇒ 不可达。**用户裁决：直接 glm-5.3-flash。**

## 2. 环境与配置

| 项 | 实测值 |
|---|---|
| LLM 代理 | `http://127.0.0.1:18080/v1`（zcode-proxy），单候选 glm-5.3-flash |
| Key | `sk-3695***f3cb`（掩码，不落全值；配置见 `llm_local_glm53_20261119.json`） |
| 靶场 | DVWA `http://127.0.0.1:8080`，phpStudy；本轮 23:07 现场启动 MySQL(3306)+Apache(8080)，登录页 HTTP 200 |
| 登录 | admin/password + 真实 CSRF token；`security=low\|medium\|high` 逐档 cookie，每案前重新登录（PHPSESSID 易失效） |
| 扫描器 | `C:/Python39/python.exe`（带 playwright + Chromium），`--headless` |
| 浏览器证据 | `evidence_class=browser-executed`，弹窗 token 命中 |

## 3. 并发约束（≤3）——如何满足

- LLM 池单候选 + 串行 failover，任一时点 1 个模型请求；本轮 `failovers=0`。
- 扫描 `--threads 2`（HTTP 并发 2）；批量脚本逐案串行，无并行 fan-out。
- 端到端 LLM 并发峰值 = 1，HTTP 并发 = 2，均未超过 3。

## 4. 实测矩阵（本轮）

| 案例 | 安全档 | finding | 严重度/置信度 | 浏览器证据 | AI 报告 | 耗时 | 备注 |
|---|---|---|---|---|---|---|---|
| low_reflected（首跑） | low | 1 | high / high | browser-executed / fired `xssv_e5a77ea8` | **降级**（120s 超时，ai_elapsed=120.05） | 135.8s | 见 §5 补跑 |
| medium_reflected | medium | 1 | high / high | browser-executed / fired `xssv_bfd72a12` | ok / used_llm / 未降级 | 112.5s | 1679 字 |
| high_reflected | high | 1 | high / high | browser-executed / fired `xssv_d5331701` | ok / used_llm / 未降级 | 98.0s | 1723 字 |
| low_stored | low | 0 | — | — | ok / used_llm / 未降级 | 58.4s | 1054 字；引擎真实结论 |
| low_reflected（补跑） | low | 1 | high / high | browser-executed / fired | ok / used_llm / 未降级 | 112.4s | `--ai-timeout 180`，1943 字 |

反射面三档（low/medium/high）均检出 1 个 high 反射型 XSS（GET 参数 `name`），全部经真实
Chromium 确认为可执行。存储面 `low_stored` 0 finding，与今早基线一致，是引擎真实结论，
不作有利化解释。

### 与今早基线（20261119b）对比

| 维度 | 20261119b | 20261119c | 结论 |
|---|---|---|---|
| 反射面检出 | 3/3 high，browser-executed/fired | 3/3 high，browser-executed/fired | 一致，无回归 |
| 存储面 | 0 finding（首跑 429 降级，补跑恢复） | 0 finding（一次成功） | 检出一致；本轮 AI 未遇 429 |
| AI 报告耗时 | 62–74s | 93–108s（low 首跑撞 120s） | 本轮本地模型明显变慢，但均为抖动非能力问题 |
| 最终 AI 成功率 | 4/4（含补跑） | 4/4（含补跑） | 一致 |

## 5. 降级归因与处置

- 唯一降级：low_reflected 首跑 `ai_elapsed=120.05` 正好撞 `--ai-timeout 120` 上限；模型没返回，
  非鉴权/非 429（本轮 `failovers=0`）。本轮整体偏慢（medium 108s / high 93s）支撑「超时抖动」判断。
- 处置：`--ai-timeout 180` 单案重跑，恢复 `ok=True / used_llm=True / degraded=False`（107.98s，1943 字）。
- **运行建议更新**：本机本地模型本轮比今早慢约 50%，建议把 AI 报告超时固定到 `--ai-timeout 180`，
  既覆盖长报告抖动，也不改判定层/语料/预算。

## 6. AI 报告质量（补跑 low_reflected 节选）

- 结构：`执行摘要 → 风险评级表 → 漏洞详情（成因/影响/复现/修复/CWE/CVSS）→ 修复优先级建议`，中文地道。
- 非权威性守住：42 请求、1 high、参数 `name`、CVSS 5.3、载荷 token 均来自引擎，模型未新增/篡改事实。
- 证据链闭合：因浏览器证据为 `browser-executed`，报告如实写出 PoC 触发 alert。
- 复现 POC 为引擎原文 curl 命令，可直接重放。

## 7. 产物清单（本轮，带后缀 20261119c）

- `dev/dvwa_headless_local_llm_20261119c.py` — 批量脚本（从 20261119b 复制，仅改 STAMP）
- `dev/dvwa_low_reflected_headless_retry_20261119c.py` — low_reflected 单案补跑脚本（`--ai-timeout 180`）
- `dvwa_{low,medium,high}_reflected_headless_ai_20261119c.json` — 三档反射面（首跑；low 含超时降级留档，不覆写）
- `dvwa_low_reflected_headless_ai_retry_20261119c.json` — low_reflected 补跑（恢复成功）
- `dvwa_low_stored_headless_ai_20261119c.json` — 存储面
- `dvwa_batch_headless_ai_20261119c.json` — 批量事实表（4 案首跑）
- 本文 `dvwa_local_llm_headless_20261119c.md`

未触碰 Phase 400 相关产品代码/测试；LLM 配置沿用 `llm_local_glm53_20261119.json`（未改 git 在途文件）。

## 8. 仍开放

- **dv4.1 flash 未参与本轮**：网关未启动，若要用需拉起 dsh harness（`dsh web`/`desktop`）并打开
  gateway 开关；用户本轮选择跳过。要做模型对比是独立一轮。
- DVWA DOM 型 XSS 模块、header/cookie 面、medium `<ScRiPt>` 大小写绕过、impossible 负对照 —— 仍未测（同 Phase 400 交接 §6）。
- 未跑全量 strict gate：本轮只做靶场端到端 + 网关实况校正，不碰判定层/语料/预算，全量门 398/399 结论仍成立。
