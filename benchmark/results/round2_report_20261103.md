# XSSentinel 第二轮改造验收报告（2026-11-03）

本报告只汇总**本轮同机实测**。仓库历史产物（如 `p352_sample_on.json`、
上一轮 64 例门禁）在引用时单独标注，不与本轮数字混算。

## 0. 中断状态对账

上一轮在 Phase 355（transport 层证据 canary）落地后停住，未写收尾报告。对账结果：

- **已完整落地**：`xssentinel/core/layers/transport_layers.py` 的 header/cookie
  all-name canary、`tests/test_phase355_transport_canary.py`（14 项，本轮复跑
  14 passed）、`tests/_p355_probe.py`（一次性诊断脚本，不被 pytest 默认收集）。
  `gate_p355_{sync,async}.json` 是上一轮产物，数值为 sync 36/0/28/0、async
  36/0/27/0（未混入本轮统计）。
- **无半截接线**：检查了 auth localStorage、async stored shim、`XSS_BUDGET_V2`
  各开关、DOM 规则收敛，均为完整调用链；transform 剪枝实验已回退，工作树不含
  该实验代码。
- **异常**：对账时发现 `benchmark/server.py`（2704 行，runner 依赖）在工作树中
  被删除。已从 HEAD 恢复（内容与 HEAD 一致，`git diff --stat` 空），否则
  `benchmark/runner.py` 无法启动。该删除不是本轮任何命令造成的，来源未能确认
  （疑似并发外部进程）；如果再次出现，应以 `git show HEAD:benchmark/server.py`
  恢复后再跑门禁。

## 1. 三项欠账核验

### 1.1 27 条官方控制例（XSSMaze v0.3.0）

命令（每条独立进程，临时目录指向 `tests/_pytest_tmp`）：

```bash
python -m xssentinel -u <control-url> -f json --progress none --log-level error \
  --max-payloads 14 --max-transforms 12 --threads 2 --timeout 10
```

| 引擎 | 控制例 | FP 实际计数 | 耗时 |
|---|---|---|---|
| sync | 27 | **0 / 27** | 50.1s |
| async | 27 | **0 / 27** | 174.6s |

判定口径：finding 类型 `reflected/stored/stored_dom/dom/dom_dynamic` 且
severity 为 medium/high/critical 才算误报。本轮数字为实测，非沿用上一轮
491.9s / 204.2s 的旧记录。

### 1.2 ruff

```text
$ .venv/Scripts/ruff.exe check .
All checks passed!
```

全仓库 0 告警，因此不存在“本次引入 vs 既有”需要区分的项；改动文件与
未改动文件均为 0。

### 1.3 路径疑点

`D:\qoder\xssentinel\xssentinel\core\scanner_layers.py` 存在；
`D:\qoder\xssentinel\xsssentinel\core\scanner_layers.py` 不存在。
上一轮清单里的三 s 路径是笔误，实际只有两 s。

## 2. 本轮改造前后对比

### 2.1 真实应用回归集 v2（Juice Shop 20.2.0 + DVWA）

同一命令：

```bash
python benchmark/realworld/run_realworld.py \
  --tools xssentinel,xssentinel-headless,dalfox,nuclei
```

| tool | TP | FN | FP | TN | blocked | recall | FPR | 耗时 |
|---|---|---|---|---|---|---|---|---|
| xssentinel | 7 | 0 | 0 | 6 | 0 | 1.000 | 0.000 | 81.1s |
| xssentinel-headless | 7 | 0 | 0 | 6 | 0 | 1.000 | 0.000 | 82.0s |
| dalfox v2.13.0 | 2 | 3 | 0 | 6 | 2 | 0.400 | 0.000 | 111.1s |
| nuclei v3.9.0 | 1 | 3 | 0 | 6 | 3 | 0.250 | 0.000 | 4.1s |
| burp / acunetix | - | - | - | - | - | - | - | `unavailable`（无安装/授权，未执行） |

新增覆盖：登录后反射（DVWA `xss_r`）、持久化反馈（DVWA `xss_s` guestbook）、
API-only（Juice `PUT /api/Products/1`）、Header 注入（Juice
`GET /rest/saveLoginIp` + `True-Client-IP`）。每例 ground truth 来自官方
challenge 目录或应用低安全级源码，并在 2026-11-03 用独立 Playwright 复核
（证据字段写在 `benchmark/realworld/cases.json`）。

dalfox/nuclei 的 3 个 DOM FN 是 `#` fragment 输入形状限制；API-only/Header
两例行对它们是 `BLOCKED`（需要认证写 + SPA 渲染），不是违约漏报。

### 2.2 40 例分层样本 A/B（XSSMaze）

同一命令、同一 40 例；A 臂只关第二轮预算（`XSS_BUDGET_V2=0`），B 臂全开：

| arm | TP | FN | FP | TN | 耗时 |
|---|---|---|---|---|---|
| base2（第二轮预算关闭） | 32 | 0 | 0 | 8 | 83.7s |
| new2（全开） | 32 | 0 | 0 | 8 | 51.8s |

- 相对本轮 A/B 基线：**83.7s → 51.8s，1.62×**
- 相对上一轮记录基线 79.7s（`benchmark/results/p352_sample_on.json`）：
  **1.54×**；绝对 51.8s 落在 40–53s 目标区间内。
- 召回/精确率不变（TP/FN/FP/TN 完全一致）。

逐例耗时显示剩余成本主要是进程启动/导入（约 36 例落在 1.0–1.6s 地板）
和 3 个必须开浏览器的 DOM 正例（`codeexec-level1` 4.2s、`dom-level6`
2.7s、`modern-bypass-level26` 3.8s），transform 阶梯已不是主成本。

### 2.3 transform 阶梯剪枝尝试（未保留）

在 `scan_param` 里按 `prioritize_transforms` 返回的恢复家族数量把
非完整反射的 transform 上限从 12 收到 `len(priority)+2`，同命令复测：

| 版本（同一时段） | TP | FN | FP | TN | 耗时 |
|---|---|---|---|---|---|
| 剪枝前 | 32 | 0 | 0 | 8 | 56.8s |
| 剪枝后 | 32 | 0 | 0 | 8 | 57.5s |

无可测量收益（差异在噪声内），按“避免过度工程”原则已回退；当前工作树
不含该实验代码。上节最终的 new2 51.8s 是回退后另一次复测，不与本表混算。

### 2.4 64 例 strict 门禁

命令：

```bash
python benchmark/runner.py --quick --strict-gate --engine sync
python benchmark/runner.py --quick --strict-gate --engine async
```

| 引擎 | TP | FN | FP | TN | SKIP | 耗时 | 结果 |
|---|---|---|---|---|---|---|---|
| sync | 36 | 0 | 0 | 28 | 0 | 134.7s | FP0/FN0/ERROR0，PASSED |
| async | 36 | 0 | 0 | 27 | 1 | 157.4s | FP0/FN0/ERROR0 over 63 scored，PASSED |

（上面为本轮最终代码的 fresh run：`gate_round3_sync.json` /
`gate_round3_async.json`。上一轮产物 `gate_p355_*` 为 153.8s / 154.9s，
数值同为 FP0/FN0/ERROR0，仅作历史对照，不与本轮混算。）

async 的 1 个 SKIP 是 `neg-stored-02` 在 manifest 中声明为 sync-only
（既有能力边界，不是回归）。

本轮首次跑 sync 门禁时抓到一个本轮引入的
`UnboundLocalError: _all_hints`（CSP no-exec / redirect landing 分支未初始化），
已修复后复跑通过；修复点见 `xssentinel/core/scanner_layers.py`。

## 3. async stored 对齐

现状代码已接线（`async_scanner.py` 在扫描末尾通过 `_AsyncScannerShim`
调用 `scan_stored_auto_pages`；shim 继承 `StoredAutoMixin` + `StoredBlindMixin`，
并合并 auth headers/cookies/localStorage）。本轮同一组 10 个 XSSMaze stored
用例实测：

| 引擎 | stored TP | FP | 耗时 |
|---|---|---|---|
| sync | 9 / 9 | 0 | 14.5s |
| async | 9 / 9 | 0 | 101.1s |

结论：**召回对齐**；async 的墙钟更慢（async 引擎在 API/DOM 页面上的固定开销），
但结果集一致。无需新增代码。

## 4. DOM 静态层可信度（第 4 项）

- 规则收敛：`document.title=`、`.val()`、非可执行 `setAttribute/attr(title)`、
  `appendChild` 不再以 medium 进入报告；`attr('href')`、`prop('innerHTML')`、
  `setAttribute('onclick')`、`innerHTML`、`document.write` 保持原等级。
- 真实页面证据：DVWA guestbook（登录 + security=low）静态层 120 条 low、
  0 条 medium/high；Juice Shop 首页/搜索页 0 条。
- 回归：`tests/test_dom_static_precision.py` 等 35 项 DOM 相关测试通过；
  `test_stored_auto_discovery` + `test_mixin_contracts` +
  `test_architecture_scale` + DOM 精度测试合并复跑 33 项通过。
- 剩余边界（计算属性名、跨语句对象身份、外部 bundle、medium=需人工确认）
  已写入 `README.md` 的「DOM 静态分析层的能力边界」。

## 5. 仍未解决的能力缺口

1. **Juice Shop 持久化反馈挑战**：即使 `NODE_ENV=unsafe`，feedback 模型仍执行
   `sanitizeHtml(comment)`，官方 `<iframe>` 被剥离；本轮实测 5 种载体
   （官方 iframe、畸形 iframe、math/table、svg/style、noscript mXSS）写入后
   comment 均被清空或只剩 `<table></table>`，admin 页面无弹窗。需要真正的
   sanitizer-bypass 而不是稳定回归夹具；该类别由 DVWA guestbook 覆盖。
2. **商业工具对跑**：Burp Pro / Acunetix 本机无安装/授权，保持 `unavailable`。
3. **多角色认证流**：目前是单账号（Juice admin / DVWA admin），未验证多角色
   越权组合。
4. **绝对提速目标已达成**：最终代码 A/B 83.7s → 51.8s（1.62×），落在 40–53s
   区间；剩余成本在进程启动与必须开浏览器的 DOM 正例，transform 剪枝无收益
   已回退。
5. async 引擎绝对耗时仍显著高于 sync（stored 101.1s vs 14.5s），只保证结果对齐。

## 6. 产物路径

- 真实应用对照：`benchmark/realworld/results/realworld_v2.json` / `.md`
- 用例与 ground truth：`benchmark/realworld/cases.json`
- 真实应用说明：`benchmark/realworld/README.md`
- 40 例 A/B：`benchmark/results/p354_sample_base2.json` /
  `p354_sample_new2.json`
- 64 例门禁（本轮 fresh）：`benchmark/results/gate_round3_sync.json` /
  `gate_round3_async.json`；上一轮对照：`gate_p355_sync.json` /
  `gate_p355_async.json`
- DOM 规则回归：`tests/test_dom_static_precision.py`
- Phase 355 canary：`tests/test_phase355_transport_canary.py`
- 本报告：`benchmark/results/round2_report_20261103.md`
