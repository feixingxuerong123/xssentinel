# DVWA × 本地 glm-5.3-flash 实测记录（2026-11-19）

本轮目标：用本地 LLM 代理（`glm-5.3-flash`，**并发不超过 3**）接入 XSSentinel 的 AI 报告链路，对 DVWA 真靶做一次端到端实测。所有数字来自本轮真实运行，未沿用旧快照。

## 1. 环境与配置

| 项 | 实测值 |
|---|---|
| LLM 代理 | `http://127.0.0.1:18080/v1`（zcode-proxy），`/v1/models` 实测列出 `glm-5.3` / `glm-5.3-flash` |
| 调用格式 | OpenAI `/v1/chat/completions`（已实测应答）；Anthropic `/v1/messages` 亦可用，但 XSSentinel AI 报告走 OpenAI 格式 |
| Key | `sk-3695***f3cb`（掩码记录，不落全值） |
| 模型 | `glm-5.3-flash` |
| 靶场 | DVWA `http://127.0.0.1:8080`，源码 `C:/pentest-targets/DVWA`，phpStudy Apache 2.4.39 + MySQL 5.7.26 |
| 登录 | admin/password + 真实 CSRF token；`security=low\|medium\|high` 逐档 cookie 切换 |
| 浏览器证据 | 本轮 Python 环境（WorkBuddy 3.13.12）**无 playwright**，headless 回放报错 ⇒ finding 的 `evidence_class=browser-unavailable`。检测判定不受影响，AI 报告如实转述该证据缺口 |

## 2. 并发约束（用户指定 ≤3）——如何满足

- LLM 池：**单候选 + 串行 failover**，任一时点只有 1 个并发模型请求；本轮 `failovers=0`。
- 扫描：`--threads 2`（HTTP 并发 2）。
- 批量脚本：**逐案串行**，一次只跑一个扫描，不做并行 fan-out。
- 结论：端到端 LLM 并发峰值 = 1，未超过 3。

## 3. AI 报告链路验证（`--ai-check`）

```
OK  local  glm-5.3-flash  sk-369***f3cb  1.3s → [+] 1/1 candidate(s) answered.
```

## 4. 实测矩阵

| 案例 | 安全档 | finding | 严重度 | AI 报告 | 模型 | 耗时 | 备注 |
|---|---|---|---|---|---|---|---|
| low_reflected（首跑） | low | 1 | high | ok / used_llm / 未降级 | glm-5.3-flash | 50.09s | 首份完整报告 |
| low_reflected（批量） | low | 1 | high | **降级**（ReadTimeout 60s） | — | 60.02s | 本地模型偶发慢 |
| low_reflected（重跑） | low | 1 | high | ok / used_llm / 未降级 | glm-5.3-flash | 89.58s | `--ai-timeout 120` |
| medium_reflected | medium | 1 | high | ok / used_llm / 未降级 | glm-5.3-flash | 53.58s | |
| high_reflected（批量） | high | 1 | high | **降级**（ReadTimeout 60s） | — | 60.02s | 同族偶发慢 |
| high_reflected（重跑） | high | 1 | high | ok / used_llm / 未降级 | glm-5.3-flash | 52.31s | `--ai-timeout 120` |
| low_stored | low | 0 | — | ok / used_llm / 未降级 | glm-5.3-flash | 19.88s | `L4_stored` 已 ran（661 请求，注入 mtxMessage），本轮未产出 finding |

反射面三档（low/medium/high）均检出 1 个 high 反射型 XSS（GET 参数 `name`），与 DVWA 的设计一致。存储面本轮 0 finding，属实测结果，不作有利化解释。

## 5. AI 报告质量（节选自 low_reflected 首跑全文）

- 结构：`执行摘要 → 风险评级表 → 漏洞详情（成因/影响/复现/修复/CWE/CVSS）→ 修复优先级建议`，中文地道。
- 非权威性守住：报告所有事实（42 请求、1 high、参数 `name`、载荷、CVSS 5.3）均来自引擎输入；对 `browser replay errored / 最强证据缺失` 如实转述，未编造执行成功。
- 复现 POC 为引擎原文 curl 命令，可直接重放。

完整正文见 `benchmark/results/dvwa_low_reflected_ai_20261119.json` 的 `ai_report.attempts[0].detail`。

## 6. 降级归因与处置

两次降级根因均为 `requests.exceptions.ReadTimeout (read timeout=60.0)`——本地 flash 模型生成长报告时耗时波动，偶发越过 60s 默认预算（首跑 50s、重跑 89.58s 均成功，证明是边界抖动，非配置/鉴权/模型能力问题）。处置：`--ai-timeout 120` 重跑，两例均恢复 `ok=True / used_llm=True / degraded=False`。cooldown 状态检查无残留（`fail_count=0`）。

**运行建议**：本机跑本地模型 AI 报告时固定 `--ai-timeout 120`，可消除该抖动。

## 7. 产物清单（本轮，带日期 20261119）

- `llm_local_glm53_20261119.json` — 本地 LLM 池配置（临时配置，未改 git 在途文件）
- `dvwa_low_reflected_ai_20261119.json` — 首跑完整报告（含高质量 AI 全文）
- `dvwa_{low,medium,high}_reflected_ai_20261119.json`、`dvwa_low_stored_ai_20261119.json` — 批量四案
- `dvwa_{low,high}_reflected_ai_retry_20261119.json` — 提高超时后的重跑
- `dvwa_batch_local_llm_20261119.json` — 批量事实表
- `dvwa_batch_local_llm_20261119.py` — 批量脚本
- `dvwa_live_cookie_20261119.txt` — 本轮会话 cookie（本机靶场专用，勿外传）

未触碰工作区既有的在途改动（Phase 400 相关产品代码/测试/文档）。
