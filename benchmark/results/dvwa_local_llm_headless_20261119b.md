# DVWA × 本地 glm-5.3-flash 实测记录（第二轮，2026-11-19b，headless 证据版）

本轮目标：在今早（`dvwa_local_llm_20261119.md`）"AI 报告链路可用"的基础上，补上**真实浏览器执行证据**——用带 playwright + Chromium 的 Python39 跑 `--headless`，让每条 finding 的 `evidence_class` 从 `browser-unavailable` 升级为 `browser-executed`，同时保持本地 LLM 报告链路与并发约束。所有数字来自本轮真实运行（2026-11-19 01:24–01:32 GMT+8），未沿用旧快照。

## 1. 环境与配置

| 项 | 实测值 |
|---|---|
| LLM 代理 | `http://127.0.0.1:18080/v1`（zcode-proxy）；本轮实测 `/v1/models` 列出 `glm-5.3` / `glm-5.3-flash` |
| 三种格式端点 | 全部实测应答 OK：OpenAI `/v1/chat/completions`、Anthropic `/v1/messages`、Responses `/v1/responses`（Codex）；XSSentinel AI 报告走 OpenAI 格式 |
| Key | `sk-3695***f3cb`（掩码记录，不落全值） |
| 模型 | `glm-5.3-flash`（单候选，串行 failover） |
| 靶场 | DVWA `http://127.0.0.1:8080`，phpStudy；admin/password + 真实 CSRF token；`security=low\|medium\|high` 逐档 cookie |
| 扫描器 | `C:/Python39/python.exe`（**带 playwright + Chromium 1223**），`--headless` |
| 浏览器证据 | `evidence_class=browser-executed`，弹窗 token 命中，报告如实写出"PoC 成功触发 alert" |

## 2. 并发约束（用户指定 ≤3）——如何满足

- LLM 池：单候选 + 串行 failover，任一时点 1 个模型请求；本轮 4 案 `failovers=0`。
- 扫描：`--threads 2`（HTTP 并发 2）。
- 批量脚本：逐案串行，一次只跑一个扫描，无并行 fan-out。
- 结论：端到端 LLM 并发峰值 = 1，HTTP 并发 = 2，均未超过 3。

## 3. 实测矩阵（本轮）

| 案例 | 安全档 | finding | 严重度/置信度 | 浏览器证据 | AI 报告 | 耗时 | 备注 |
|---|---|---|---|---|---|---|---|
| low_reflected | low | 1 | high / high | **browser-executed / fired** `xssv_8d81ca55` | ok / used_llm / 未降级 | 77.3s | |
| medium_reflected | medium | 1 | high / high | **browser-executed / fired** `xssv_63dcfe11` | ok / used_llm / 未降级 | 78.7s | |
| high_reflected | high | 1 | high / high | **browser-executed / fired** `xssv_ee1e17d9` | ok / used_llm / 未降级 | 67.1s | 报告 1591 字，`fact_warnings=[]` |
| low_stored（首跑） | low | 0 | — | — | **降级**（HTTP 429 / code 3008 `user concurrency limit exceeded`，0.22s） | 44.6s | 本地代理并发窗口抖动 |
| low_stored（补跑） | low | 0 | — | — | ok / used_llm / 未降级（33.28s，702 字） | 71.0s | 等 20s cooldown 后单案重跑恢复 |

反射面三档（low/medium/high）均检出 1 个 high 反射型 XSS（GET 参数 `name`），且**全部经真实 Chromium 确认为可执行**——这是相对今早那轮的核心增量。存储面 `low_stored` 0 finding：`L4_stored=1`（层已执行）、`L4_stored_failed=0`、665 请求、`scan_status=completed`，是引擎真实结论，不作有利化解释。

## 4. 降级归因与处置

- 三档反射面 + 存储面补跑：`ok=True / used_llm=True / degraded=False`，模型 `glm-5.3-flash`，无降级、无 failover。
- 唯一一次降级是 `low_stored` 首跑命中本地代理 `429 user concurrency limit exceeded`（错误码 3008，0.22s 立即失败，非 read timeout）。等满 20s cooldown 后单案重跑恢复，证明是代理侧并发窗口抖动，非配置/鉴权/模型能力问题。
- **运行建议**：本机跑本地模型 AI 报告固定 `--ai-timeout 120`；若偶发 429，等待 ~20s cooldown 后单案重跑即可。

## 5. AI 报告质量（节选 high 案）

- 结构：`执行摘要 → 风险评级表 → 漏洞详情（成因/影响/复现/修复/CWE/CVSS）→ 修复优先级建议`，中文地道。
- 非权威性守住：`fact_warnings=[]`、`finding_count` 等于引擎输入数；42 请求、参数 `name`、CVSS 5.3、载荷 token 均来自引擎，模型未新增/篡改事实。
- 证据链闭合：因本轮浏览器证据为 `browser-executed`，报告如实写出"PoC 载荷成功触发 `alert('xssv_ee1e17d9')`，证实脚本可执行"——今早那轮因 `browser-unavailable`，报告只能转述证据缺口。
- 复现 POC 为引擎原文 curl 命令，可直接重放。

## 6. 产物清单（本轮，带后缀 20261119b）

- `dvwa_{low,medium,high}_reflected_headless_ai_20261119b.json` — 三档反射面（含 headless 证据 + AI 报告）
- `dvwa_low_stored_headless_ai_20261119b.json` — 存储面首跑（429 降级留档，不覆写）
- `dvwa_low_stored_headless_ai_retry_20261119b.json` — 存储面补跑（恢复成功）
- `dvwa_batch_headless_ai_20261119b.json` — 批量事实表（4 案）
- `dev/dvwa_headless_local_llm_20261119b.py` — 批量脚本
- `dev/dvwa_low_stored_headless_retry_20261119b.py` — 单案补跑脚本

未触碰工作区既有的在途改动（Phase 400 相关产品代码/测试/文档）；仅新增上述带日期产物。LLM 临时配置沿用今早的 `llm_local_glm53_20261119.json`。
