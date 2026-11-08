# 外部 CLI 型智能体调用实测（2026-11-07）

## 归属与边界（先说清楚，避免证据被误用）

- 调用方是**独立于项目代码的 CLI 型智能体进程**：通过真实 shell 调
  `python -m xssentinel`，只看 stdout / stderr / exit code / 落盘文件；
  MCP 一轮由 shell 手发 JSON-RPC 帧，**没有复用** `dev/cli_compat_probe.py`
  或任何项目自带 probe。这比"注入流单测"真实，但**不是第三方 GUI 客户端**
  （Claude Desktop / Cursor / Qoder）接入实测，也不是第三方 MCP SDK 协议栈。
- 靶场：仓库自带 `dev/_ui_scan_target.py`，`127.0.0.1:18941`，
  `/echo` 未转义反射（正例）、`/safe` `html.escape`（负例）、`/dom`。
- 环境：`.venv/Scripts/python.exe` = Python 3.12.10，`xssentinel.__version__`
  = **1.4.4**。`git status` 显示 **Phase 364 的 5 个源码文件与 11 个产物处于
  未提交状态**（head `221b875` 是 Phase 363），CHANGELOG 最新发布章节仍是
  `[1.4.3]`，`AGENTS.md` 状态段写 1.4.2。⇒ **本次实测跑在 WIP 工作区，
  不是已发布版本**；`mcp_server.py`（缺陷所在）不在修改清单里，属已提交代码。
- 调用前统一 `export NO_PROXY=127.0.0.1,localhost`，避免出口代理污染 loopback。
- 未跑：MCP over HTTP、全量 194 例门禁、任何 GUI 客户端接入。

## 逐项结果

| # | 调用 | rc | stdout | 结论 |
|---|---|---|---|---|
| 1 | `-u .../echo?q=hello -o - -f json` | 0 | 10399 B，纯 JSON | 1 finding / high / `browser-unavailable`；摘要全在 stderr |
| 2 | `-u .../safe?q=hello -o - -f json` | 0 | 8097 B，纯 JSON | 0 finding（负例无误报） |
| 3 | `printf ... \| --batch-stdin -o - -f json` | 0 | 2 行 / 18494 B | JSONL 逐行可解析，注释行被跳过，findings `[1, 0]` |
| 4 | 无目标 `-o - -f json` | 2 | **0 B** | stderr 一行短提示，无 `--help` 倾倒 |
| 5 | `--verify-fix 01_echo.json -o - -f json` | 1 | 3031 B | `Fixed 0 / Still vulnerable 1 / Error 0`；rc=1 是 CI 门语义，非崩溃 |
| 6 | `--diff 01_echo.json 02_safe.json -o - -f json` | 0 | 2894 B | `Fixed 1 / New 0 / Regressed 0` |
| 7 | 批量 `-o - \| head -c 120` | PIPESTATUS `0 0 0` | — | stderr `[!] stdout consumer closed (broken pipe); stopping output.` |
| 8 | CWD 检查 | — | — | 无 `-` / `-.json` / `-.csv` 残留 |
| 9 | 5 个报告帧 UTF-8 解码 | — | — | 全部 OK |
| 10 | MCP stdio 一轮（6 帧） | 0 | — | `initialize` 回 `2025-06-18`/serverInfo 1.4.4；`tools/list` 7 工具；`server/discover` 现代帧回 5 个 `supportedVersions`；错拼键 `params` 回 `isError=True` + `accepted: cookies, headers, param, timeout, url; aliases ...`；`scan` 回 1 finding |

**CLI 管道契约（Phase 359/360/362）在真实外部调用下全部成立**：stdout 只有报告帧，
人类文本全在 stderr，退出码语义可依赖，断管不算失败，编码与文件副作用都干净。
`[*] System temp dir not writable; using ...` 这类环境告警也正确落在 stderr。

## 两个实测缺口（不是读码推断，是本次跑出来的）

### 缺口 1：`xssentinel_profile` 在带查询串的 URL 上给出相反的廉价门结论（漏报风险）

同一目标 `http://127.0.0.1:18941/echo?q=hello`：
- CLI `scan` → **1 个 high reflected XSS**（步骤 1）
- MCP `scan` → **1 个 finding**（步骤 10）
- MCP `profile` → **`reflected: false`**，note `the parameter is probably not rendered`（步骤 10）

A/B 对照（同一工具，只改 URL 形态）：

| profile 的 `url` | `reflected` |
|---|---|
| `http://127.0.0.1:18941/echo?q=hello` | **False** |
| `http://127.0.0.1:18941/echo` | **True**（`meta_chars` 正常给出） |

根因在 HTTP 层，与判定函数无关。`run_profile_tool`（`mcp_server.py:1169`）用
`requester.request("GET", url, params={param: probe_value})`，而 `url` 里已带
`?q=hello` ⇒ requests 追加而非替换：

```
final_url  ...?q=hello&q=xssp_abcd1234%22%27%3E%3C...
token_in_response False
body       <div id='out'>hello</div>
```

靶场（以及多数服务端）取第一个同名参数，探针值根本没进响应。对照：
`run_scan_tool`（`mcp_server.py:1032-1043`）先用 `urlparse` 把 query 拆成
`params`、把 `base_url` 去掉 query 再交给引擎，所以能检出 —— **同一契约在两个工具里
手写了两遍，一边替换一边追加**。

影响：`skills/xssentinel-mcp/SKILL.md:25` 明确教 Agent "**Cheap gate: profile
before scanning**"，而 `scan` 的 inputSchema 又写 "Query parameters are picked up
as injection points"。Agent 按指南把带查询串的目标 URL 传给 profile，会拿到
`reflected: false` 并跳过扫描 ⇒ **静默漏报**，且工具返回的是肯定句而非"不确定"。

最小修法：`run_profile_tool` 复用 `run_scan_tool` 的 URL 拆分（剥掉 query、
目标参数用 probe 替换、其余参数保留），并加一条带查询串 URL 的行为回归。
按项目规矩，这属于判定入口行为变化，改完要跑受影响层单测 + 全量门。

### 缺口 2：同一漏洞，两条接入面给的能力不等（MCP 拿不到 PoC）

| 字段 | CLI JSON 报告 | MCP `scan` 的 finding |
|---|---|---|
| `poc` / `poc_verified` / `poc_verify` / `proof` / `replay` | **有** | **无** |
| 其余判定字段 | 有 | 有（12 个） |

`mcp_server.py:832-850` 的 `_compact_finding` 把 PoC 与 proof 当 "delivery
machinery" 裁掉。于是"可复现 PoC"这条自定基线只在 CLI 面成立；Agent 拿到判定
却拿不到复现物，且 MCP 工具面没有报告/导出工具可补。REST 有
`/api/v1/scans/{id}/report`，MCP 没有对应入口。

### 附带记录（低优先级，非缺陷）

- `README.md:453` 把 rc=1 写成"崩溃"，但 `--verify-fix` 用 rc=1 表达
  "仍有漏洞"的 CI 门语义（步骤 5 实测）。属文档措辞，不是崩溃。
- 版本不同源（`__version__` 1.4.4 / CHANGELOG 1.4.3 / AGENTS 1.4.2）是
  Phase 364 WIP 的自然状态；`test_changelog_latest_version_matches_package_version`
  当前会红，发版时两处一起改即可。按项目"带日期历史记录不回改"的规矩，本轮不动文档。

## 对"可被智能体 CLI 调用的辅助工具"这一定位的回答

**调用面已经成立**：CLI 管道 9 项契约、MCP stdio 完整一轮（含自纠正握手与
dual-era 发现）都由外部调用方实测通过。**但工具面语义还不配叫"可靠辅助"**：
缺口 1 会让遵循 SKILL.md 的 Agent 主动跳过真漏洞，优先级高于补 PoC 工具，
也高于改 README 首屏。先用一次真实任务把 Agent 的决策链跑出来，再改定位口径。

## 复现

```bash
cd /d/qoder/xssentinel
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
.venv/Scripts/python.exe dev/_ui_scan_target.py &          # 18941
.venv/Scripts/python.exe -m xssentinel -u 'http://127.0.0.1:18941/echo?q=hello' -o - -f json > r.json 2> r.err
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xssentinel_profile","arguments":{"url":"http://127.0.0.1:18941/echo?q=hello","param":"q"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"xssentinel_profile","arguments":{"url":"http://127.0.0.1:18941/echo","param":"q"}}}' \
  | .venv/Scripts/python.exe -m xssentinel --mcp
```

原始帧与报告落在本机
`C:/Users/Administrator/AppData/Local/Temp/xss_agent_e2e_20261107/`（工作区外，
避开 safe-delete 配额），未纳入仓库。

---

## 修复与验收（同日，Phase 365；缺口 1 已修）

### 改动范围

- 新增 `xssentinel/core/target_url.py::split_target_url` —— **一个定义**：
  剥掉 query/fragment，返回 `(base_url, params)`；重复键保留第一个值，
  query 值不做 URL 解码（与 `scan` 历史行为一致，requests 会重编码）。
- 四个调用点收口：
  | 调用点 | 修前 | 修后 |
  |---|---|---|
  | `run_scan_tool` | 手写拆分（正确） | 调共享 helper，行为不变 |
  | `run_profile_tool` | `request(url, params={param: probe})` 追加 | 剥 query + **替换**目标键 |
  | `run_verify_tool` GET | 同上 | 同上；headless replay 同步改用 `base_url` + 合并后的 params |
  | `propose_and_verify` GET | 同上 | 同上；headless replay 同步 |
  | 上述工具的 POST | `url` 原样 + body | **不变**（body 是独立通道，不与 query 冲突） |
- 检查过未改的两个：`param_mine` 追加的是**不同名**的候选参数（不会遮蔽），
  `csp_analyze` 只 GET 原 URL 且不注入 ⇒ 不受这个缺陷影响。
- 新增 `tests/test_phase365_mcp_url_parity.py`：4 个真实 loopback 行为测试
  （取第一个同名参数的服务端）、6 组 helper 纯函数用例、2 个**源码级守卫**
  （四个函数体都调 `split_target_url`；任何 `request` / `verify_headless`
  调用点的 URL 实参不得仍是裸 `url`）。函数本体不会腐化，调用点会。

### 证据链

1. **修前先红**：`3 failed, 1 passed` —— profile / verify / propose 三个断言失败，
   scan 那条一直绿；pytest 日志抓到
   `/echo?q=hello&q=xssp_ffbe7009%22...`。
2. **修后**：4 passed → 补齐纯函数与源码守卫后 **7 passed / 0 skip**。
3. **变异对照 4/4**（`phase365_mutation_check.py`，落工作区外 TEMP）：
   baseline 绿 → 改回旧行为红 → restored 绿，四组分别是 profile 追加、
   verify 保留 live query、propose 追加、**helper 本体把 query 拼回 base_url**
   （最后一组让 4 个行为测试全红，证明 helper 是根因）。按字节替换、
   `finally` 还原、锚点不唯一即 ABORT。变异脚本里禁用 rerun 插件会踩
   `pyproject.toml` 的 `reruns = 1` strict ini（INTERNALERROR），改用
   `-o reruns=0`。
4. **回归组 15 文件 237 passed / 0 skip**（MCP 协议/参数/进度/预算/信任边界/
   双协议 + llm_propose + reflection/profile + evidence grading +
   CLI 359/360 守卫）；**ruff 全仓 `All checks passed!`**。
5. **外部调用复测**（帧落 `10_after_fix.jsonl`）：
   profile 带 query / 不带 query **都 `reflected: true`**（A/B 收敛）；
   verify 带 query `reflected=true, confirmed=true`；scan 1 finding；
   错拼键仍 `isError` + accepted 清单（自纠正未坏）；
   CLI `-o - -f json` rc=0、stdout **10399 B 与修前逐位一致**、1 finding、
   `has_poc=True`（CLI 侧零变化）。

### 门禁取舍（明说，不拿"跑过"充当"绿"）

**本轮未跑全量 194 双引擎 strict 门**：该矩阵走 CLI / 引擎扫描路径，
**不调用任何 MCP 工具**，对本次改动覆盖为零；拿它当验收等于用一个
测不到改动面的绿数字充证据。替代覆盖是「CLI 侧输出逐位不变 + 237 例
回归 + 真实外部调用复测」。若按发版口径仍要补，入口是
`dev/gate_run_scratch.py --strict-gate --port 189xx`（约 13–16 分钟/引擎，
报告目录指工作区外以避开 safe-delete 配额）。

### 仍未修

**缺口 2（MCP finding 无 PoC / 工具面无报告导出）本轮未动**：那是新增能力，
不是缺陷修复，按项目「搬代码与改逻辑绝不混在同一轮」应单独决策；
且要不要补，最好等一次真实 GUI Agent 任务测出 Agent 是否真的需要 PoC。

CHANGELOG / AGENTS.md 状态段本轮**未改**：工作区处于 Phase 364 WIP
（Unreleased 为空、版本 1.4.4 与 CHANGELOG 1.4.3 不同源），发版时统一收口，
不擅自替维护者改文档口径。

---

## 补测：CLI 型智能体的完整任务链（同日，修正上一轮的结论）

### 先纠正一个判断错误

修复段落末尾曾写「下一步真正有价值的是接一次真实 GUI Agent（Qoder /
Claude Desktop）」。**这个说法是错的**：WorkBuddy 自身就是 CLI 型智能体，
前面所有调用已经由它真实发起；GUI 宿主多出来的只有协议协商与模型自主选
工具，对「能不能当辅助工具」不是必要条件。缺的只是**根据工具返回结果
自主调整并重试**的那半条链，且这条链同样可以自己跑完。本段补上，
并据此修正定位结论。

### 四步闭环（每一步都由调用方读上一步结果后决定）

| 步 | 调用 | 返回 | 调用方的决策 |
|---|---|---|---|
| A | `xssentinel_profile`（带 `?q=hello`） | `reflected=true`、`context=html_element`、`raw=""'><>()=/;`"` | 元字符全放行 ⇒ 值得全量扫 |
| B | `xssentinel_scan` | 1 finding / **high** / `browser-unavailable`，载荷 `<img/src="x"/onerror=alert('xssv_...')//>`；**无 PoC 字段** | 不照抄，换载荷家族自己试 |
| C | `xssentinel_verify` ×2 | ① 自造 `<svg/onload=alert(1)>` → `reflected=true, confirmed=true, evidence=model-only, context=event_handler`；② 故意无执行点的 `just-a-string-no-sink` → `confirmed=false` + note `payload has no execution point ... never confirm execution` | 假设被确认一次、被工具**否定**一次 ⇒ 裁决权在工具，不在我 |
| D | CLI `-o - -f json` + `--verify-fix` | 报告带 `poc`(curl+URL) / `poc_verified=true` / `poc_verify` / `proof`(含 snippet) / `replay`(curl+browser_url)；复验 rc=1 `1 finding(s) still exploitable` | 交付复现物并闭环 |

证据帧：`12_agent_stepA.jsonl` / `13_agent_stepB.jsonl` /
`14_agent_stepC.jsonl` / `15_agent_final.json` / `16_verifyfix.json`
（均在 `C:/Users/Administrator/AppData/Local/Temp/xss_agent_e2e_20261107/`）。

### 修正后的定位结论

**「可以被智能体 CLI 调用的辅助工具」这个定位现在成立**：智能体主导编排
（画像 → 决定扫 → 换载荷 → 重试 → 出复现物），工具给出确定性裁决并会
否定智能体的错误假设；接入契约、协议代际、参数自纠正、退出码与报告帧
全部由真实外部调用验证过。缺口 1（profile 廉价门误判）已修并有守卫。

**缺口 2 的性质随之降级**：MCP 侧拿不到 PoC 不再是「可靠性问题」，
而是**一条可量化的多跑一跳**——步骤 D 实测，Agent 只需再调一次 CLI
就能拿到完整复现物（curl / URL / proof snippet / browser_url）。
补 MCP 报告工具属于便利性与能力对称，不是定位成立的前提；优先级
低于「真实任务里 Agent 是否真的频繁需要 PoC」这个尚未测量的需求。

**仍未做、但已确认不构成必要条件**：第三方 GUI MCP 宿主的协议协商实测。
若将来要补，验证的是宿主侧行为，不是本工具能否被调用。
