## Phase 346:HEAD 全量门禁复验 + 一个被"绿门禁"掩盖的真缺陷（浏览器 launch 失败泄漏 driver）

**起因**:Phase 345 之后累积了 4 个未过全量门禁的提交（`569ba69` 卫生 / `8bb9fd4`
drain 修复 / `e7cc1d8` cryptography / `793535b` 文档蒸馏），按"「绿」和「跑过」是
两个词"的纪律，HEAD 只能声称"d81a6e5 全量绿 + 后续改动按文件复验"。本轮补这一轮
证据。

### 1. 重定向 TEMP 的门禁:258/258 绿,exit 0

`TEMP=<repo>/dev/_pwtemp` 下跑 `python tests/run_all_batched.py --quiet`：
**258/258 文件绿 4554s,exit 0**,失败 none,skip **75 个 / 10 文件**,其中 2 个
整文件零贡献(`test_nuclei_import` 1 缺 PyYAML、`test_stored_e2e_acceptance` 3
需 `XSSENTINEL_STORED_E2E=1`)。

3 次 attempt 0 超时 / attempt 1 绿（**全部为单文件预算超时，不是判定面回归**）:
`test_layer_guard` 541s（复跑 11 passed 0.45s）、
`test_phase209_spa_route_delivery` 627s（复跑 4 passed 86s）、
`test_phase307_encoding_shapes` 548s（复跑 33 passed 10.19s）。

skip 逐条归因（全部有声明，无一个是"悄悄没跑"）:benchmark_fp 27 例 loopback 声明
跳过 + 复跑 **94 passed**；dom_engine_probe_urls 4 / parity_full_matrix 1 /
stored_e2e 3 需显式 opt-in 环境变量；htmlunsafe 4、header_slice 2、phase209_accept_encoding 1、
passive_mitm 1（POSIX 位）为平台/依赖声明。

### 2. 真缺陷:launch 失败后 playwright driver 与 loop 一起泄漏

**发现路径不是读代码，是测量**:本轮在**默认环境**（不重定向 TEMP）跑门禁时，
`test_async_dom_live` 确定性失败 `playwright Error: BrowserType.launch: EPERM:
mkdtemp 'C:\...\Temp\playwright-artifacts-XXXXXX'`。追查这个 EPERM 时量出真正的问题:

`get_shared_browser()` 里 `pw = sync_playwright().start()` 成功后，
`pw.chromium.launch()` 抛出，而 `_TLS.pw = pw` 写在 launch **之后**——实例无人
登记。实测（修复前）:

```
launch failed as expected: Error  BrowserType.launch: EPERM ...
_loop_running after failure: True        <-- greenlet loop 留在本线程
_TLS.pw set?  False                      <-- 没有任何指针指向它
registered browsers: 0
node.exe now: node.exe 19676 ...         <-- driver 进程存活
shutdown_thread_browser() ->             <-- 收不回来
_loop_running after shutdown: True       <-- 仍然是 True
```

**为什么这是最坏的形状**:任何用户只要 chromium 没装、被杀软拦、或被沙箱拒绝
temp，这一次失败就会永久污染该线程——之后每个 `asyncio.run()` 都报 "cannot be
called from a running event loop"，而错误信息只说"浏览器不可用"。这是 silent-FN
方向（Phase 224 同族）。

**修复**(`dom_engine.py`,+12 行):launch 包 try/except，`except BaseException`
里先 `pw.stop()` 再 `raise`；`pw.stop()` 自身失败**不得**替换原始 launch 错误
（那才是调用方要读的原因）。

### 3. 守卫测试:三遍变异对照

`tests/test_shared_browser_recovery.py` 新增 2 例:
`test_failed_launch_stops_the_driver_it_started`、
`test_a_failed_stop_never_masks_the_launch_error`。

**变异对照(实测)**:摘掉 `pw.stop()` → `assert 0 == 1` 红，报错文案正是
"the driver started by this call was never stopped"；还原后 **5 passed**，
`dom_engine.py` SHA256 `B3D1B888...` 修复前后逐字节一致。

**顺带修掉一个测试隔离缺陷**:新用例首次跑是红的，原因不是产品——`_ALL_BROWSERS`
是模块级全局，前一个用例成功 launch 后留下的条目让"本调用没有登记任何实例"这条
断言失败。`clean_tls` fixture 改为快照/恢复 `_ALL_BROWSERS`。**这是测试状态泄漏，
不是被测代码缺陷**，如实记在此处而不是当成修复的一部分。

### 4. 第二层:仓库树的 Low 完整性标签让子进程写不进 %TEMP%

修完泄漏后，默认环境的 DOM 测试仍然 11 failed——但 skip 从 **33 降到 0**：
失败从"悄悄跳过"变成"真的跑了然后红"，这是诚实化，不是恶化。继续归因:

三解释器对照实验（`dev/_ilcheck.py`，同一台机、同一脚本）:

| 解释器 | 进程完整性 | 写 %TEMP% |
|---|---|---|
| `Programs\Python\Python312\python.exe`（树外） | HIGH (12288) | OK |
| 同一 exe 复制进仓库 | LOW (4096) | PermissionError |
| 同副本 `icacls /setintegritylevel Medium` | MEDIUM (8192) | OK |

即：**树内文件带 Low 标签（`icacls` 可见 `Mandatory Label\Low Mandatory Level:(I)(NW)`，
`.venv` 与全部 `.exe` 同），Windows 把标签传给子进程，Low 进程不能写 Medium 的
%TEMP%**。Playwright 用 `tempfile.mkdtemp()` 建 driver 目录，于是每一个真浏览器
测试都在 mkdtemp 上死掉。

**处置选择**:不改树标签（12562 个条目，且可能被设置它的工具重新施加，会掩盖真实
能力差异）。改为在 `tests/conftest.py` 装一个**可写 TEMP 回退**:只有 `%TEMP%`
真的不可写时才启用，健康机器零变化。

**2026-11-01 独立复核（换一个解释器重做同一实验）**：用 `.venv/Scripts/python.exe`
（树内解释器）对 `%TEMP%` 做一次真写入，结果与上表一致且两个探针陷阱同时复现：

```
venv 解释器: TEMP 不可写 -> PermissionError [Errno 13] Permission denied: 'C:\...\AppData\Local\Temp'
os.access 怎么说: True          <-- 同一个目录，ACL 说可写，写不进去
```

即：回退**确实在被启用**（否则默认环境下的 `test_async_dom_live` 不可能通过，
见第 6 节），而 `os.access` 在**这一台**机器上仍然答错——不是偶发，是稳定分歧。
这条复核的价值在于它换了调用者（系统 python 可写 / venv python 不可写），
排除了"探针自己错了"的可能。


**这里踩了两个探针陷阱，两个都是"测了表示没测被测物"**:

1. `os.access(path, os.W_OK)` —— 答的是 ACL，**看不见完整性标签**，在坏机器上报
   True。实测:同一个 `%TEMP%`，`os.access` True 而 `open()` PermissionError。
2. `tempfile.gettempdir()` —— **不是** %TEMP%。%TEMP% 不可用时 Python 自己回退到
   CWD，于是探针写进了仓库、写成功了、报告"环境健康"，而浏览器的 node driver
   直接读 `TEMP` 环境变量、没有这个回退——照样 EPERM。

**修正**:探针直接读 `TEMP`/`TMP` 环境变量并**真写一个文件**（不是 access 检查）。

### 5. 守卫:两条变异都必须红（含一条修复后补上的空转）

`tests/test_temp_probe_contract.py` 6 例，其中
`test_the_documented_gate_command_gets_a_usable_temp` 起**子解释器**跑真实
import-time 行为，不重实现探针。

变异对照**两轮，第二轮抓到一个空转守卫**:

- 变异 1（改回 `tempfile.gettempdir()`）→ **2 failed**，如预期红。
- 变异 2（改回 `os.access`）→ **5 passed 全绿**——守卫**空转**。原因:`os.access`
  对不存在的路径本来就返回 False，而原有用例只覆盖了不存在的路径。**它唯一答错的
  场景（存在、ACL 可写、写不进去）正是本轮要修的那个**，于是补
  `test_probe_believes_the_write_not_the_acl`（monkeypatch `open` 对目标目录抛
  PermissionError）→ 重跑变异 2 **1 failed**，还原后 **6 passed**。
- 教训与 Phase 201 「守卫空转的五种失效形状」同族：**变异活着 ≠ 用例写对了，
  先问这个变异在什么输入下才与正确实现分歧**。

### 6. 本轮口径与未做的部分

- 门禁 1（重定向 TEMP）:258/258 绿 exit 0，4554s，skip 75/10 文件。
- 门禁 2（默认环境）:在本条写入时正在后台跑，结果见下一条记录；**本条不预先
  声称它绿**。
- 本机 loopback 抖动仍存在：`test_dom_sink_matrix` 曾出现 20 分钟 0 CPU 卡在
  `socket.socketpair()`→`lsock.accept()`（pytest-timeout 线程栈实测），
  同时 `dev/_loopback_now.py` 独立探针报 HEALTHY——**同一时段两种答案**，
  说明是间歇性而非持续劣化。按纪律记为环境，不当回归。
- `tests/_pytest_tmp/` 是新的测试副产物目录,**已补进 .gitignore**(带注释,
  与 conftest 的 `_temp_is_writable` 对应);本日志初稿写"待补"时尚未提交,
  复核时已落地,故此处更正为已完成。
- 开发脚本 `dev/_ilcheck.py`、`dev/_mutate_temp_probe.py`、`dev/_loopback_now.py`
  按 `_` 前缀约定不入库。
