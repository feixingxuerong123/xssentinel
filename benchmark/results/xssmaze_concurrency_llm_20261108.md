# XSSMaze 外部靶场：并发 ≤3 与本地 LLM 网关实测（2026-11-08）

> 性质：诊断性抽样实测，**不是官方 scorecard**。所有数字来自本轮自己的运行。
> 凭据仅落在 TEMP 的临时池配置，未写入仓库、未提交。

## 口径与边界

| 项 | 值 |
|---|---|
| 靶场 | 官方 XSSMaze 容器 `127.0.0.1:3001`，`/map/json` 实测 1064 endpoints（server 1040 / client 24；exploitable 1037 / 27） |
| 抽样 | 固定 seed `20261108`，`server` reach + `GET`，按 `type` 分层，**86 例**（60 vulnerable + 26 controls），覆盖约 65 类靶点 |
| Ground truth | **只**取 `/map/json` 的 `vuln.exploitable`，绝不从扫描结果反推 |
| 扫描入口 | 真实 CLI `python -m xssentinel --batch <urls> --batch-workers N -o - -f json`（JSONL），非自写线程池 |
| 判定口径 | 每个 `target` 的 `findings[]` 非空 = 检出（与官方 wrapper 的 per-URL 口径等价） |
| LLM | 本地网关 `http://127.0.0.1:18080/v1`，模型 `glm-5.3-flash`；临时池 + key 只在 `C:/Users/Administrator/.cache/xssentinel/tmp/` |
| 不可比 | 官方 scorecard 串行跑 1013 例；本轮是 86 例诊断抽样，**不可与 F1 0.965/0.978 直接比较** |

## 1. 网关可用性

- `/v1/models` 200，列出 `glm-5.3` / `glm-5.3-flash`。
- 三协议 POST 探测全 200：`/v1/chat/completions` 3.15s、`/v1/responses` 1.15s、`/v1/messages` 1.63s。
  （项目 LLM 池只用 OpenAI 兼容的 chat/completions，另外两个地址本轮仅测可达性，未做产品内接入。）
- **3 路并发短请求**：全 200，0.96 / 1.23 / 1.39s，均返回 `OK`。
- `--ai-check`：`1/1 candidate OK`，1.8s，key 在输出中自动脱敏。

## 2. 扫描并发 1 / 2 / 3（同一批 86 例）

| `--batch-workers` | wall | TP | FP | TN | FN | R | P | findings | requests | `partial` | requests_failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **34s** | 59 | 0 | 26 | 1 | 0.9833 | 1.0000 | 96 | 3799 | 14 | 26 |
| 2 | **22s** | 59 | 0 | 26 | 1 | 0.9833 | 1.0000 | 96 | 3799 | 14 | 27 |
| 3 | **19s** | 59 | 0 | 26 | 1 | 0.9833 | 1.0000 | 96 | 3799 | **16** | 29 |

- **判定逐位一致**：以 `(type, severity, param, url, confidence, evidence_class)` 组成稳定签名，
  `W1 vs W2` 与 `W1 vs W3` 的差异目标数均为 **0 / 86**（排除随机 token 字段）。
- W3 相对 W1 提速 **1.79×**，但只比 W2 快 3s。
- `partial` 真因**不是并发**：14–16 个全部是
  `InvalidSchema: No connection adapters were found for "javascript:..."`
  ——扫描器把 `javascript:` 伪协议当成 HTTP 目标发出。W3 新增的 2 个
  （`nonce/level2`、`metarefresh/level2`）是同一缺陷在更多目标上显现。
- 唯一 FN 三档完全一致：`domsink/level2`（`scan_status=completed`、33 请求、0 失败），
  属真实漏报，不是环境或并发伪影。

## 3. AI 叙事开 / 关对照（单目标 `api-response/level5`）

| | wall | findings | `ai_report` |
|---|---|---|---|
| 不带 AI | 1s | 1 | 无该字段 |
| `--ai-report` | 64s（LLM 62.76s） | 1 | `ok=True, used_llm=True, degraded=False, provider=local, model=glm-5.3-flash, failovers=0, fact_warnings=[]` |

- findings 稳定签名（含 `poc_html` / `proof` 存在性）**逐位一致**；报告唯一新增字段是 `ai_report`。
- 符合设计：`--ai-report` 只写散文，findings / severity / URL / PoC 全来自确定性引擎。

## 4. AI 长生成并发边界（本轮核心结论）

| 并发 | `--ai-timeout` | 结果 |
|---|---|---|
| 1 | 90 | **成功** 62.8s，`used_llm=True` |
| 2 | 90 | **2/2 降级**：90.02 / 90.03s，`all candidates failed (timeout x1)` |
| 3 | 90 | **3/3 降级**：约 92s，同上 |
| 3 | 180 | 1 路成功（**95.61s**），2 路 `rate_limit x1`（0.11 / 0.20s 即失败） |
| 批量 `--batch-workers 3` + AI | 90 | **3/3 降级**，rc=0、93s，findings 仍完整（1 / 1 / 8） |

⇒ **该网关对长生成请求的有效并发约为 1**。短请求 3 并发全绿、长生成 2 并发就互相拖过 90s、
3 并发时多余请求被判 `rate_limit` ⇒ 限的是推理槽位，不是 TCP 连接数。
所有降级都是**设计内 fallback**：扫描结果、PoC、退出码均不受影响，只是报告没有 LLM 章节。

## 5. 本轮发现但未修的缺陷

1. `InvalidSchema`：`javascript:` 伪协议被当作 HTTP 请求目标，导致 14–16 / 86 个目标
   `scan_status=partial`。属请求构造层，与并发无关，建议单独一轮修 + 回归。
2. `domsink/level2` 稳定 FN（三档、33 请求、0 失败）——DOM sink 类的真实漏报。

## 6. 取舍建议

- **扫描并发取 2**：22s、`partial` 与串行同为 14；并发 3 只再快 3s，却多 2 个 `partial`，不值。
- **AI 报告并发取 1**，`--ai-timeout` 至少 120s（单路 62.8s，拥塞时成功那路 95.6s）；
  批量模式不要叠加 `--ai-report`。
- **别指望 LLM 改善检出**：设计上不参与判定，本轮开关对照也证实零差异。
  它的价值只在叙事与 `propose`（提议载荷仍由 token oracle 裁决）。
- 下一轮更值钱的是：修 `javascript:` scheme 跳过，以及跑官方 1013 例全量 scorecard，
  而不是再调并发档位。

## 7. 局限

- 抽样 86 例、分层但**非官方 runner 记分**；GT 虽独立，检出判定由本轮脚本完成。
- 网关为本机单实例，结论不外推到公网 / 多实例部署。
- 未测 Anthropic / Responses 协议在**产品内**的接入（项目池不支持）。
- Docker 真实应用靶（Juice Shop / DVWA / bWAPP）本轮未启动，未测。
- 未做 `--ai-report` 与扫描并发 3 之外的组合（如 W2 + AI），按上表可推但**未实测**。
