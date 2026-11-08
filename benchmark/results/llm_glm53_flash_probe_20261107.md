# GLM-5.3-Flash 实测（2026-11-07）

> **补充（同日 03:05，本地网关）**：用户提供的本地 OpenAI 兼容网关
> （`http://127.0.0.1:18080/v1`，模型 `glm-5.3-flash`）**完全可用**：
> `xssentinel_propose` 5 候选 → **4 确认 / 1 否定**；`--ai-report` 93.7s、
> `fact_warnings=[]`、判定与 PoC 不变。下面「先说结论（仅云池）」只适用于
> **AMD Radeon Cloud**，本地网关的完整数据见文末「本地网关实测」。
> 两条路径结论相反，别混用。

## 先说结论（仅云池）

**AMD 云池上的 GLM-5.3-Flash 能连通，但当前不能承担真实生成：ping 3.2s 正常，
真实请求把 600 个 completion token 全烧在 reasoning 上，正文 0 字。** 项目的
`truncated_response` / `pool exhausted` 判定是对的，不是缺陷。

**XSS 检测能力不经过 LLM**：判定由 token oracle（`verifier.verify_semantic` /
`verify_headless`）给出，LLM 只在 `--ai-report`（叙事）、`--ai-check`（体检）、
`xssentinel_propose`（提议载荷，再由引擎裁决）三处出现。所以「用 GLM 测检测
能力」严格说是错位的——换任何模型，扫描结果都一样。

## 环境事实

- 本机**没有本地推理服务**：无 `ollama`，11434 / 1234 / 8000 均无监听；
  也没有 `XSSENTINEL_LLM_CONFIG` / `XSSENTINEL_LLM_KEY_*` 环境变量。
- `xssentinel/data/llm_providers.json` **不存在**，只有
  `llm_providers.example.json`；example 里 GLM-5.3-Flash 有两条：
  `amd/GLM-5.3-Flash`（直连）与 `nvidia/z-ai/glm-5.3-flash`（NIM）。
  所以「本地的 GLM」实际是**配在本地文件里的云 API**，不是本地权重。
- 本轮用 TEMP 下的独立 pool（只启用 amd 的 GLM-5.3-Flash），
  通过 `--ai-config` / `XSSENTINEL_LLM_CONFIG` 注入，**未改动仓库、未落 key**。

## 实测结果

| 项 | 命令 | 结果 |
|---|---|---|
| 连通性 | `--ai-check --ai-config <tmp> --ai-timeout 60` | **OK / amd / GLM-5.3-Flash / 3.2s**（回复把 reasoning 前言也带出来了） |
| NVIDIA 同族 | 同上 | **timeout / z-ai/glm-5.3-flash / 61.7s** |
| 真实生成（propose 的同一 prompt，838 字符） | 直连 `/chat/completions`，`max_tokens=2000` | **ReadTimeout 120s** |
| 同上，`max_tokens=4000` | 同上 | **ReadTimeout 120s** |
| 同上，`max_tokens=600` | 同上 | **HTTP 200，但 `finish_reason=length`、`completion_tokens=600`、`reasoning_tokens=601`、`content_len=0`** |
| MCP `xssentinel_propose`（5 候选） | 临时 pool，`XSSENTINEL_LLM_CONFIG` | `isError: LLM pool exhausted: all 2 attempt(s) failed` |
| `--ai-report`（LLM 不可用时） | 扫描 + `--ai-report --ai-timeout 45` | **rc=0**，报告 12664 B；`used_llm=false`、`error=all candidates failed (timeout x1)`、`degraded` 标记；**finding 仍 1 个 high** |

## 结论与建议

1. **别把 GLM-5.3-Flash 当 `--ai-report` / `propose` 的主力**。它与
   example note 里记录的 sensenova `glm-5.2` 是同一形态：预算被 reasoning
   频道吃掉，正文拿不到。项目的 `MIN_REPORT_CHARS` / `truncated_response`
   正是为这类模型准备的，所以才会 failover 而不是产出一份空报告。
2. **要 LLM 辅助，按 example 的实测排序选**：`deepseek-v4-flash`（质量最好，
   但真实输出偶发超时/空 body）或 AMD `MiniCPM5-2B`（稳，实测写出过 1517 字
   报告；会泄漏 reasoning 前言，`report_ai.clean_completion` 会剥掉）。
3. **检测能力的验证与模型无关**：直接跑靶场 / 194 例基准即可；
   `--ai-report` 挂了只影响叙事章节，判定、severity、PoC 全部不变
   （本轮实测：rc=0、1 个 high、报告完整）。
4. 如果你另有**本地 vLLM / Ollama** 的 GLM 权重，把 OpenAI 兼容端点填进
   pool 即可（`base_url` 如 `http://127.0.0.1:11434/v1`，`models` 填
   `ollama list` 里的名字）；但那属于另一个待测对象，本轮没有这个服务。

## 复现

```bash
# 1) 体检（只启用 GLM-5.3-Flash 的临时 pool）
python -m xssentinel --ai-check --ai-config /path/to/glm_pool.json --ai-timeout 60
# 2) 真实生成（观察 reasoning 吃掉预算）
#    用 xssentinel.core.llm_propose.build_messages 构造同一 prompt，直连
#    <base_url>/chat/completions，看 usage.reasoning_tokens 与 content_len
# 3) 端到端（LLM 挂掉时的降级）
python -m xssentinel -u http://127.0.0.1:18941/echo?q=hello \
  -o - -f json --ai-report --ai-config /path/to/glm_pool.json \
  --ai-model GLM-5.3-Flash --ai-timeout 45
```

原始产物：`18_ai_report.json` / `18_ai_report.err` / `17_propose_out.jsonl`
（`C:/Users/Administrator/AppData/Local/Temp/xss_agent_e2e_20261107/`）。

---

## 本地网关实测（2026-11-07 03:05，用户提供）

端点 `http://127.0.0.1:18080/v1`（OpenAI 兼容；另有 Anthropic 格式
`http://127.0.0.1:18080` 与 Responses 格式 `/v1/responses`，本轮只用 OpenAI 格式）。
本轮用 TEMP 下独立 pool（`--ai-config` / `XSSENTINEL_LLM_CONFIG` 注入），
**未改动仓库、未把 key 写入任何仓库文件**。

### 基础连通性

| 项 | 结果 |
|---|---|
| `GET /v1/models` | 200 / 0.02s，列出 `glm-5.3`、`glm-5.3-flash` |
| ping（16 token，"reply ok"） | 200 / **3.0s**，`content="ok"`，reasoning 53 字符 |
| propose 同款 prompt（838 字符，`max_tokens=3000`） | 200 / **68.5s**，reasoning 14756 字符，**正文 243 字符**（合法 JSON 数组，5 条） |

### MCP `xssentinel_propose`（真实检测入口）

`pool={"model":"glm-5.3-flash","failovers":0}`；`parsed=5 / verified=5 / rejected=0`。

| 模型提议的载荷 | 引擎裁决 |
|---|---|
| `<svg/onload=alert(1)>` | **confirmed**（`event_handler`） |
| `<details/open/ontoggle=alert(1)>` | **confirmed**（`event_handler`） |
| `<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>` | **confirmed**（`onbegin` handler） |
| `<style/onload=alert(1)></style>` | **confirmed**（`event_handler`） |
| `<iframe/srcdoc='<svg/onload=alert(1)>'>` | **not confirmed** — `sandbox: no executable node carries the token` |

这是「模型提议、引擎裁决」最完整的一次实测：**5 条里 4 条真的执行，1 条被
确定性判定否定**；`confirmed` 列表来自 token oracle，不是模型自评。

### `--ai-report`（叙事，不改判定）

- `used_llm=true`、`model=glm-5.3-flash`、`provider=local`、**93.7s**、0 failover
- `markdown` **1912 字符**，内容与引擎一致：1 个 high、19 次请求、无 WAF、
  载荷原样、并正确复述「本次未做浏览器回放验证，实际可利用性待人工复核」
- **`fact_warnings=[]`**（模型没有编造 URL / 载荷）
- 报告 18282 B；**finding 仍 1 个 high、`has_poc=true`** ⇒ 判定与 PoC 不受 LLM 影响

### 一个待观察的边界（未改代码）

`core/llm_propose.py` 把 LLM 调用超时**写死 `timeout=60`**。本次 propose 成功，
但同一 prompt 的首次直连耗时 **68.5s**，已经越过 60s 线——冷启动或更慢的
本地模型会被 `ReadTimeout` 砍掉，表现为 `pool exhausted` 而不是"模型慢"。
建议下一轮把它做成可配置（读 `--ai-timeout` / pool.timeout），并加一条
「慢模型不被误判为不可用」的回归；本轮只记录，不擅自改判定入口。

### 复现

```bash
# 本地池：providers[0].base_url = http://127.0.0.1:18080/v1
#           models = ["glm-5.3-flash"]，key 用网关的 sk-...
python -m xssentinel --ai-check --ai-config /path/to/local_pool.json --ai-timeout 120
# MCP propose（pool 从 XSSENTINEL_LLM_CONFIG 注入）
XSSENTINEL_LLM_CONFIG=/path/to/local_pool.json python -m xssentinel --mcp < propose_frame.jsonl
# 报告叙事
python -m xssentinel -u http://127.0.0.1:18941/echo?q=hello -o - -f json \
  --ai-report --ai-config /path/to/local_pool.json --ai-model glm-5.3-flash --ai-timeout 120
```

原始产物：`19_local_propose.jsonl` / `20_ai_report_local.json` / `20_ai_report_local.err`。
