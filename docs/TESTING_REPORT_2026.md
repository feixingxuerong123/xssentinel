# XSSentinel 测试与交付报告（2026-10-09）

> 一句话结论:**「给一个目标,直接产出一份漏洞报告」这条链路已被端到端验证成立**;
> 本轮同时修掉 3 个 P0 缺陷,其中 2 个是"静默说谎"级别的——
> 它们让扫描在**根本没碰到目标**时报告"0 漏洞,一切正常"。

---

## 1. 交付目标验证:一条命令 → 一份报告

用 `dev/_delivery_check.py` 实测（真实靶场 fixture，非 mock）：

```
[1] 一条命令 -> 一份报告 (html)      exit=0  46948 B
[2] 报告点名了脆弱端点              findings=1  first: reflected high /search
[2b] 默认(无 --exit-code)            rc=0  —— 漏洞仍写入产物,门禁是可选的
[3] 安全端点不误报                  findings=0
[4] 六种格式全部产出
    html      47599 B   json    14110 B   csv   493 B
    sarif      2621 B   junit    639 B    md    916 B

DELIVERY MET
```

实际命令就是产品既有入口，无需新增代码：

```bash
python -m xssentinel -u "<url>" -o report.html
```

> 一处需要澄清的既定设计:`exit 1`（发现漏洞）由 `--exit-code N` **显式开启**,
> 默认扫描无论有无发现都返回 0——这是刻意的,避免把"跑完了"和"有漏洞"混成一个信号。
> 需要 CI 门禁时显式加 `--exit-code 1` 即可(已验证返回 1)。

---

## 2. 本轮修掉的 P0（全部经 mutation 验证为 load-bearing）

### P0-1 熔断器看不见"沉默的失败" → 死靶扫描卡死 >180s

`CircuitBreaker.record()` 只收 HTTP **状态码**。连接被拒 / IP 被封 / DNS 黑洞不产生状态码,
于是失败计数恒为 0,熔断器永不跳闸,扫描对一个已经拒绝连接的靶点反复重发。

**实测**:同步引擎打一个死端口,从 >180s 挂死 → **36.1s 正常退出 3**。

改动:
- `budget.py`:新增独立计数轨 `record_transport_failure()` / `_transport_fail_times`,
  `transport_threshold` 默认 `min(threshold, 5)`
- `requester.py`:`_send` 的兜底 `except` 在 `tally.failed += 1` 后调用
  `_post_record_failure()` → `breaker.record_transport_failure()`
- `async_scanner.py`:新增 `_transport_threshold` 与 `_record_transport_failure()`,对称接线

**为什么两条轨分开**:5xx 说明**这个端点**坏了,其余端点可能还好,值得继续;
沉默说明**整个目标**不应答,应当立刻停。两者该用不同的停止阈值。

回归测试:`tests/test_circuit_breaker_transport.py`（9 passed）,含
`test_the_next_request_is_refused_before_being_sent` 证明跳闸后**不再发包**。

### P0-2 async 引擎的流量数���传不到完整性闸门 → "没扫到"被读成"扫过了"

`_run_async_scan` 构造的 shim 上挂着一个真实 `Requester`,但 async 扫描本身走 aiohttp,
那个计数器永远是 0。读成 0 = "什么都没发",于是 async 扫死靶:
**报告写 0 findings、退出码 0**——和"扫干净了"完全无法区分。

改动:`cli_runner.py` 把 async 引擎自己的计数拷进 shim 的 tally。
关键点是 `attempted` 必须计入**已发出但抛异常**的请求——`requests_made` 只在拿到响应后才加,
所以原来死靶时 `attempted=0`,正好是"什么都没发"的形状,闸门被自己的正确性保护骗了:

```python
failed = getattr(asc, "failed_requests", 0) or 0
shim.req.tally.attempted = asc.requests_made + failed   # 发出过 = 尝试过
shim.req.tally.failed = failed
```

修复前后（`dev/_egress_probe.py`）:

| | 修复前 | 修复后 |
|---|---|---|
| sync 死靶 | rc=3 incomplete=True | rc=3 incomplete=True |
| **async 死靶** | **rc=0, offline_notice=True** | **rc=3, incomplete=True** |

### P0-3 `_sync_layers_online` 被伪造传输层骗过 → 测试套件无限挂死

Phase 200 的 hermeticity 守卫本意是:线程卸载出去的**同步** page 层不得真的发包。
但标志位在进入 `async with aiohttp.ClientSession(...)` 时就置 True——
测试里替换的假 aiohttp 照样把它翻成 True,同步层于是拿着真 `Requester` 去
`socket.getaddrinfo` 干等。

**实测**:`tests/test_async_budget.py` 从**永久挂死** → **11 passed in 0.86s**。

我第一版守卫用 `aiohttp_mod.__name__ != "aiohttp"` 判定,**可被 `types.ModuleType("aiohttp")` 绕过**,
是我自己写的测试抓出来的。定稿版本同时校验模块身份与 `ClientSession` 的来源:

```python
if _sys.modules.get("aiohttp") is not aiohttp_mod:
    return False
real_session = getattr(aiohttp_mod, "ClientSession", None)
if real_session is None or not isinstance(real_session, type):
    return False
if not isinstance(session, real_session):
    return False
return getattr(real_session, "__module__", "").split(".")[0] == "aiohttp"
```

### P0-4（修复过程中引入、已当场修掉）完整性闸门被 Mock 打崩

P0-2 的守卫写的是 `_att > 0`。`attempted_requests` 是 tally 上的 property,
调用方注入的 scanner(MagicMock)在那里返回 MagicMock,`MagicMock > 0` 直接 `TypeError`,
`test_p25.py::test_batch_continues_past_failing_target` 当场红。

**这说明闸门本身的形状有问题**:它跑在每个批处理目标里,遇到读不懂的东西必须降级为
"无证据",而不是把扫描带崩。定稿用 `isinstance` 收敛为数值域:

```python
_att_count = _att if isinstance(_att, int) and not isinstance(_att, bool) else None
```

**mutation 验证**:把守卫去掉,`test_p25` 与新增的
`tests/test_completeness_gate_robust.py` **同时复现 TypeError 变红**;装回去,75 passed。

---

## 3. 回归验证:真实靶场零退化

### range3（26 例 × sync/async = 52 行）

`dev/_range_diff.py range3/results_baseline_2026.json range3/results_after_2026.json`:

| engine | 指标 | 修复前 | 修复后 | 变化 |
|---|---|---|---|---|
| sync | TP | 20 | 20 | — |
| sync | TN | 6 | 6 | — |
| sync | FP / FN | 0 / 0 | 0 / 0 | — |
| async | TP | 18 | 18 | — |
| async | TN | 5 | **6** | **+1** |
| async | **ERROR** | **1** | **0** | **−1** |

唯一的 verdict 变化:`async|r3-neg-unauth  ERROR → TN`（改善）。
**没有任何一例从通过变成不通过。**

### range4（React `dangerouslySetInnerHTML` / Vue `v-html` vs 转义孪生体,全 `--headless`）

`dev/_range_diff.py range4/results_baseline_2026.json range4/results_after_2026.json`:

| engine | 指标 | 修复前 | 修复后 | 变化 |
|---|---|---|---|---|
| sync | TP / TN | 2 / 2 | 2 / 2 | — |
| async | TP | 1 | **2** | **+1** |
| async | TN | 1 | **2** | **+1** |
| async | **ERROR** | **2** | **0** | **−2** |

变化的两例:`r4-pos-vue-vhtml  ERROR → TP`、`r4-neg-vue-vtext  ERROR → TN`（均为改善）。
基线里那两个 `timeout after 240s` 这次全部消失,runner 整体 **exit 0**。

浏览器确认是真的跑起来了——每个正例 12 条 finding **全部** `headless_outcome: fired`:

```
[sync ] r4-pos-react-dsi   TP  confirmed=12  16.7s  reflected×11 + dom_dynamic/Element.innerHTML, 全 fired
[sync ] r4-pos-vue-vhtml   TP  confirmed=12  16.3s  同上, 全 fired
[async] r4-pos-react-dsi   TP  confirmed=12  33.6s  reflected/script_block×11 + dom_dynamic, 全 fired
[async] r4-pos-vue-vhtml   TP  confirmed=12  19.5s  同上, 全 fired
[sync ] r4-neg-react-text  TN  confirmed=0   10.2s
[sync ] r4-neg-vue-vtext   TN  confirmed=0   35.3s
[async] r4-neg-react-text  TN  confirmed=0   11.1s
[async] r4-neg-vue-vtext   TN  confirmed=0   11.1s
```

这条正是竞品对比里那条空档的直接证据:**静态收敛之后再用真浏览器确认**。
DalFox 没有浏览器执行(官方文档:static parse of a real response, not browser execution),
这里是真执行出来的。

**range3 + range4 合计:两引擎 60 行全部 TP/TN,零 FP、零 FN、零 ERROR、零 SKIP 之外的异常。**

---

## 4. 测试套件:177 文件分批全跑

单次 `pytest tests` 在本机会跑数小时且会被单个卡死的文件拖死,因此改为逐文件批次
（`dev/_batched_suite.py`,每文件 420s 上限,**测不到 = UNKNOWN,绝不记作 pass**）。

```
PASS=172  FAIL=5  SLOW=0  UNKNOWN=0   files=177
```

5 个失败逐个定性（"失败"必须回答"谁的错"）:

| 文件 | 批次内 | 单独跑 | 定性 |
|---|---|---|---|
| `test_p25.py` | FAIL | **71 passed** | **我的回归,已修复**(P0-4) |
| `test_api_ai_report.py` | FAIL | **26 passed** (23s) | 负载相关:120s 期限在压力下不够 |
| `test_p27_api.py` | FAIL | **87 passed** (48s) | 负载相关 |
| `test_vuln_server_concurrency.py` | FAIL | **6 passed** (5.7s) | 负载相关 |
| `test_skip_params.py` | FAIL(97s,需人工 kill) | **5 passed** (0.33s) | 本机 loopback 退化 + 扫描器合规缺陷,均已修复,见下 |

新增测试文件:
- `tests/test_circuit_breaker_transport.py` — 9 passed
- `tests/test_completeness_gate_robust.py` — 4 passed

### 本机环境事实（不是代码缺陷，已实测）

`dev/_loopback_health.py`:

```
socket.socketpair()        5/5 ok,  0.00s
asyncio.new_event_loop()   3/3 ok,  0.00s
connect 到已关闭的回环端口   2.05s / 2.05s / 2.05s   <-- 异常
真实 loopback HTTP 往返      0.02s
```

**回环端口被拒要花 2.05 秒才报出来**（正常应瞬时）。这解释了为什么
碰死端口的用例在本机格外慢,以及 `tests/conftest.py` 为什么要用 `SOCKETPAIR_OK` 门控 53 个文件。

### `test_skip_params.py` 的真实病因与修复（Phase 184/185）

此前把本文件的 97s 卡死归因为 `socket.socketpair → accept`,**错**。
用 `dev/_count_real_requests.py` 实测(替换 `HTTPAdapter.send` 计数):

```
probed: [('q', False), ('bio', True)]
real requests: 41 in 252.70s
first URL: http://127.0.0.1:1/?q=1          <- L1 已过滤(Phase 184)
jsonp URL: http://127.0.0.1:1/?q=1&callback=...  <- 干净
无 Track=2 / CSRF=t
```

**真相:41 次真实网络请求全打在已关闭的回环端口上,每次约 2.05s
(Phase 184 之前的版本)**,合计逾 250s,与线程栈无关。

真正发现的是**产品合规缺陷**,不是测试问题:
Phase 184 只过滤了迭代列表,`_scan_jsonp`、CSP、CORS、XS-Leaks 等旁路层
与 `_scan_param` 的探针请求仍在**线上**重放原始查询串,
把操作员用 `--skip-param` 明确要求不外泄的名字(sessionid 之类)
重新送了出去 —— 这正是该开关存在的意义。

Phase 185 的修法(同步 / 异步各一处):

- `xssentinel/core/scanner_layers.py` — `_drop_skip_params()` +
  `AdvancedLayerMixin._skip_filtered()`,按**原始 params 字典**丢键,
  不做 URL 字符串级剥离。`dev/_url_roundtrip_probe.py` 实测:
  18 条 payload URL 里 13 条会被 `parse_qsl`+`urlencode` 往返改写,
  所以字符串级方案会静默损坏 payload,已否决。
- `xssentinel/core/scanner.py` — L1 迭代与 `_scan_param` 探针同时过滤。
- `xssentinel/core/async_scanner_layers.py` — `_drop_skip_params()`,
  `_scan_reflected` 绑定过滤后的参数对,供下游所有 async 旁路层使用。

测试本身随后改为**完全不碰网络**(`_FakeReq` 记录实际发出的键),
0.33s 且结果稳定。

双向变异验证(证明守卫是承重的,不是装饰):

| 注入变异 | 结果 |
|---|---|
| 同步 `_skip_filtered` 改为直接返回 | `test_sync_probe_loop_honours_skip_params` **FAIL**:`skipped param 'Track' still transmitted on the wire` |
| 异步 `_scan_reflected` 去掉 `_drop_skip_params` 绑定 | `dev/_async_skip_leak_probe.py` **LEAKED**(157 个请求全部带 `Track`) |
| 恢复原状 | 5 passed / clean(exit 0) |

我一度以为这是浏览器进程泄漏,用 `dev/_browser_leak_probe.py` 实测排除:
DOM sink matrix 17 例跑完 142.71s,**残留浏览器进程 0 个**。
此前观察到的 10 个 `chrome-headless-shell` 全部来自我**强制 kill** 的运行。

### 并发对本机测试结果的影响(必须知道,否则会把环境问题当成代码问题)

同一时刻本机还有**另一个项目**(`D:\qoder\vuln-agent`)在跑批量 pytest。
9 个进程时,我的验证命令 CPU 冻结在 2.01 不动,`--timeout=120` 命中,
栈落在 `asyncio/windows_events.py:783  GetQueuedCompletionStatus`——
阻塞在 Windows 异步 I/O 路径,不是被测代码。

等它降到 4 个进程后重跑,同一组用例:

```
81 passed, 18 skipped in 1.22s        (之前:timeout, exit 1)
tests/test_circuit_breaker_transport.py:  9 passed in 80.34s
```

**所以:本机上任何"卡死/超时"的测试结论,都必须先确认没有别的负载。**
之前 range3 `r3-neg-unauth` 的 ERROR、range4 两个 Vue ERROR、以及 3 个 API 用例的 flake,
都是同一类成因;其中 range3/range4 的两个已在**独占**环境下重跑验证为真实改善。

---

## 5. 竞品对比

详见 `docs/COMPETITORS.md`。先纠三个前提错误:

| 常见误写 | 实况 |
|---|---|
| `Sw33tLie/XsSer` | **404**;真实项目是 [`epsylon/xsser`](https://github.com/epsylon/xsser) |
| `JAEGER Security Research/gospider` | **404**;已迁至 [`jaeles-project/gospider`](https://github.com/jaeles-project/gospider) |
| `kheper` XSS 扫描器 | **GitHub 上不存在**(`q=kheper+xss` → `total_count: 0`) |

并且 **DalFox v3 已从 Go 完整重写为 Rust**(v3.2.4,2026-10-07),自报 XSSMaze 97.8%。
该赛道实际只有 DalFox 与 nuclei 仍在周更;XSStrike 15k star 却已一年半无更新,
GoSpider / XSLeaks 早已停更。

**对本次工作的直接影响**:报告层(六格式 + SARIF + baseline + 会话检查)已是 DalFox 标配,
**已持平,不再投入**。可守的空档是三条:
(a) 静态收敛后接浏览器确认的**两段式流水线**(市场现状是二选一,中间地带无人占据);
(b) **CSP nonce 泄露利用链**(全部竞品零覆盖);
(c) **中立横向 benchmark**(XSSMaze 只能测 DalFox)。

---

## 6. 已知未覆盖项(诚实边界)

- **`range5/` 不存在**:该目录当前只有一个空的 `vendor/`,无 runner / manifest / server。
  「全部真实靶场」在本轮实际覆盖的是 range3 + range4 + `benchmark/`。
- **竞品同靶跑分沿用 README 中既有的 60 例结果**,本轮未重跑(需外部工具链:
  `go install dalfox` + nuclei 二进制)。
- **浏览器层**本轮只在 range4 上实测;`test_dom_sink_matrix.py` 单独跑 17 passed / 142.71s,
  但在本机与其它任务并发时会被拖慢。
- 3 个负载相关 flake 未修——它们是**测试期限**问题(120s/240s 在本机不够),
  不是被测代码问题;修它们需要按最坏并发重设期限,属于独立的测试基建改动。

---

## 7. 复现命令

```bash
# 交付链路(核心验证)
python dev/_delivery_check.py

# 完整性闸门语义:两引擎对死靶都必须 exit 3
python dev/_egress_probe.py

# 熔断器:死靶必须在被拒前跳闸
python dev/_breaker_probe.py

# 真实靶场
python range3/runner.py --engine both --timeout 120 -o range3/results_after_2026.json
python range4/runner.py --engine both --timeout 240 --out range4/results_after_2026.json
python dev/_range_diff.py <baseline.json> <after.json>

# 测试套件(分批;本机需关掉 loopback 门控)
$env:XSSENTINEL_FORCE_SOCKETPAIR="bad"
python dev/_batched_suite.py

# 本机环境事实
python dev/_loopback_health.py
python dev/_browser_leak_probe.py
```

---

## 补记(2026-10-09 下午,Phase 209):上面那句"已端到端验证成立"的证据当时只到 fixture

本报告第 1 节用 `dev/_delivery_check.py`(本仓自写 fixture 起服)证明了
"一条命令 → 一份报告"的**链路**成立,这是有效结论;但它**不能**证明判定在真实
应用上说真话。下午把同一个判定拿去打 OWASP Juice Shop 20.2.0(第三方真实应用),
立刻量出四个 fixture 结构上测不到的缺陷:

1. **critical 假阳性**:模板 SSTI 判定的 `detect_rendered()` 是一句
   `"49" in response_text`,而真实靶场 406 错误页唯一的 `49` 是栈行号
   `route.js:149:13` —— 探针被**原样回显**、没有任何引擎在渲染,evidence 却写
   "rendered to 49"。已改为差分对照(同参数发无数字值)。
2. **SPA hash 路由发现不了**:默认 `crawl_engine=auto` 走 SpaCrawler,而它完全不挖
   JS —— 真靶实测 74 端点 / **0 个带 fragment**;手工给 `/#/search?q=` 则 11.4s
   拿到 browser-executed high。已接线到三条爬取路径并加按名守卫。
3. **`--async` 对整台真实靶场失效**:aiohttp 声明 `br` 却解码不了(`Brotli` 包的
   `process()` 只收 1 个参数)→ 每个响应 `400`,374 请求 0 结果。已改为只声明
   实测能解码的编码,并带"声明 br 就会炸"的反向对照。
4. **async 发现端点但不检查它们**:爬到即只跑反射层,而 fragment 参数只有浏览器
   读得到。fragment 这一支已修(现 `--async` 同一命令给出 high/high
   browser-executed),非 fragment 的更大一支记在 `docs/OPTIMIZATION.md` 2.1.1。

交付证据(真实应用,非 fixture):
`python -m xssentinel -u http://127.0.0.1:18900 -c --headless -o report.html`
→ 1 条 `dom_dynamic` high/high **browser-executed**,落在上游 `challenges.yml`
列出的 `localXssChallenge` 面;两个 sink(sync=`#/search?q=`、async=`#/track-result?id=`)
均经独立 Playwright 复核为 parsed 而非 escaped。完整记录见 `AGENTS.md` Phase 209。
