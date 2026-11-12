# XSSentinel 交付验收报告 · 2026-11-12

- tree: 交付终树（本轮改动全部落地后；提交前 `2ceee95` + 本轮改动）
- version: **1.5.0**（`__version__` / dist 元数据 / CLI `-V` / CHANGELOG 四处同源）
- verdict: **可交付**。全部数字来自本轮在这棵终树上的自跑；**不引用 11-10 在
  `edfe91d` 旧树上跑出的 299 文件 / 194 例数字**。
- 口径：重活串行（基准与套件不并行）；除显式 A/B 对照外一律
  `env -u PYTHONPATH` 干净环境；`TEMP`/`TMP` 指向工作区外可写 scratch；
  全量分批加 `PYTEST_ADDOPTS` 关闭 pytest tmp 自动清理。

---

## 1. 交付边界：本轮落地了什么

| 类别 | 内容 |
|---|---|
| 定版 | `[Unreleased]` 收成 `[1.5.0] - 2026-11-12`（按「新增能力走 minor」），保留空 `[Unreleased]` 段；`__version__` 1.4.4 → 1.5.0 |
| 打包缺陷修复 | `pyproject.toml` 新增 `[tool.setuptools.exclude-package-data]`，排除 `data/llm_state.json` / `data/llm_providers.json` |
| 新守卫 | `tests/test_package_data_hygiene.py`（3 例）、`tests/test_phase382_juice_render.py`（8 例） |
| 产物收口 | `benchmark/run_juice_render.py` + `juice_render_20261110.{json,md}` 入库；11-10 两份 HTML 报告移进 gitignore 的 `benchmark/results/_local_archive/` |
| 文档 | AGENTS.md 当前状态、CHANGELOG 1.5.0 章节与「验收(交付轮)」、OPTIMIZATION §8.15 |
| 未改 | 检测判定层、legacy MCP 帧、CLI 参数契约、历史跑分数字、CI 配置 |

无破坏性变更。版本同源守卫 `test_doc_gate_parity.py::test_changelog_latest_version_matches_package_version` 绿。

---

## 2. 门禁结果（本轮自跑，绿一律连 skip 数一起报）

| 门禁 | 结果 | skip |
|---|---|---|
| ruff 全仓 E/F/W | `All checks passed` | — |
| 结构 / 文档 / 新守卫 7 文件 | **41 passed / 0 failed** | 0 |
| quick 64 `--strict-gate` sync | TP36 / FP0 / TN28 / FN0，**64 scored**，FP0 FN0 ERROR0，exit 0 | **0 SKIP** |
| quick 64 `--strict-gate` async | TP36 / FP0 / TN27 / FN0，**63 scored**，FP0 FN0 ERROR0，exit 0 | **1 SKIP** |
| 全量分批门禁（干净 env） | **301/301 文件绿**，468s，failures 0，exit 0 | **13 例 / 6 文件**（其中 2 个整文件零贡献） |
| full 194 `--strict-gate` sync | TP113 / FP0 / TN81 / FN0，F1 **1.0000**，**194 scored**，exit 0 | **0 SKIP** |
| full 194 `--strict-gate` async | TP107 / FP0 / TN75 / FN0，F1 **1.0000**，**182 scored**，exit 0 | **12 SKIP**（sync-only） |
| range3 `--engine both` | sync TP19/FP0/TN7/FN0/ERR0；async TP17/FP0/TN7/FN0/ERR0，exit 0 | async 2 SKIP |
| range4 `--engine both` | 双引擎各 TP2/FP0/TN2/FN0/ERR0，阳性 `browser-confirmed=12/12`，exit 0 | 0 |
| range5 `--engine both` | 双引擎各 TP1/FP0/TN1/FN0/ERR0，exit 0 | 0 |
| range6 `--engine both` | 双引擎各 TP1/FP0/TN1/FN0/ERR0，exit 0 | 0 |
| 打包冒烟 | wheel `1.5.0` 可构建、解压后 import / `-V` 正常、2 个 console script 齐全 | — |

**整文件零贡献**：`test_oracle_default_sent.py`(3) 与
`test_stored_e2e_acceptance.py`(3) 被 runner 计入「绿」但什么都没贡献；
runner 自己打了 `! 2 file(s) contributed nothing to this gate`。
「301/301 绿」与「skip 13 例 / 6 文件」必须一起引用，不可只报前者。

---

## 3. 唯一红的 A/B 归因（不是回归）

首轮全量门禁（带宿主注入的 `PYTHONPATH` shim）为 **300/301、484s**，
唯一红 `test_phase360_cli_compat.py` 的 `--version` / `-V` 两例：

```
assert r.stderr == b""
E  assert b"Error in si...omize.py'\r\n" == b''
```

stderr 内容是 `sitecustomize.py` 的 `PermissionError`，来自
`D:\Program Files\WorkBuddy AI\...\cli\vendor\shim`（Low 完整性标签读不到），
与被测 CLI 无关。同一棵树、只改环境变量：

| 对照 | 命令 | 结果 |
|---|---|---|
| A 原环境 | 带 `PYTHONPATH` shim 单跑该文件 | **2 failed / 32 passed / 2 rerun**，rc 1 |
| B 干净环境 | `env -u PYTHONPATH` 单跑同文件 | **34 passed / 0 failed**，rc 0 |

干净环境下 `python -m xssentinel -V` 输出 `xssentinel 1.5.0`。
⇒ 环境形态，不是产品回归，也不是 1.5.0 定版引起；交付口径取 B 那轮
（301/301）。这与 AGENTS.md 记录的 `test_phase327` loopback 环境形态同类，
按「A/B 定性 + 不当绿也不当回归」处置。

---

## 4. 本轮发现并修复的真实缺陷：wheel 夹带运行期状态

初版打包冒烟（修复前）用 `uv build --wheel` 构建 1.4.4 wheel，
`unzip -l` 发现 `xssentinel/data/llm_state.json` 被 `package-data` 的
`data/*.json` 通配打进制品。该文件被 `.gitignore` 忽略，内容是
provider 失败计数 / 错误文本；同类的 `llm_providers.json` 若存在则含 API 密钥。
**`.gitignore` 对构建没有约束力。**

修法不是「以后小心」，而是两处清单用守卫钉在一起：
`exclude-package-data` 显式排除两者，`test_package_data_hygiene.py`
要求 `.gitignore` 里的 `xssentinel/data/*.json` 规则与排除清单**逐项相等**
（单向漂移、集合增删、名单被掏空、通配被移除都会红）。

终树复验：`xssentinel-1.5.0-py3-none-any.whl` 的 `data/` 只剩 8 个
语料/模板文件，**无** `llm_state.json` / `llm_providers.json`。

**变异对照**（两处新守卫各一组，源码/产物字节均还原）：

| 守卫 | baseline | mutated | restored |
|---|---|---|---|
| `test_package_data_hygiene.py` | 3 passed, rc 0 | 改掉一个排除项 → 2 failed, rc 1 | 3 passed, rc 0，`BYTEWISE_IDENTICAL` |
| `test_phase382_juice_render.py` | 8 passed, rc 0 | `counts.browser_executed` 2→3 → 2 failed, rc 1 | 8 passed, rc 0，`BYTEWISE_IDENTICAL` |

Phase 382 守卫调的是真实 `to_markdown(json)`（与产物 MD 逐字节比对），
并用 AST 反查 runner 仍监听 `page.on("dialog")`、仍有
`control_contaminated` 分支——不是只验报告里的自述文本。

---

## 5. 本机环境与口径（复现者必读）

- **`PYTHONPATH` shim**：宿主注入，会让每个 Python 子进程 stderr 多一条
  `PermissionError`。跑门禁前 `env -u PYTHONPATH`，否则 CLI stderr 断言必红。
- **`%TEMP%` 不可写**：`tempfile.gettempdir()` 会静默回退到仓库根；
  而 `dev/gate_run_scratch.py` 直接读 `os.environ["TEMP"]`。本轮把
  `TEMP`/`TMP` 指到 `D:/qoder/_xssentinel_delivery_scratch` 再跑，
  `xssentinel_gate` 结果目录才能落盘。
- **safe-delete 守卫**：`--jobs 4` 需配
  `PYTEST_ADDOPTS='-o tmp_path_retention_policy=all -o tmp_path_retention_count=10000'`
  与 `dev/batched_gate_scratch.py`（日志重定向到工作区外），否则出成片假红。
- **pip 通路病态**：`pip wheel` / `pip install --target` 在本机数分钟级挂起
  （与 CONTRIBUTING 记录同形）。构建改用 `uv build --wheel`，安装冒烟改用
  解压 wheel + `PYTHONPATH` 导入，等价且秒级。
- **本机 editable 元数据**：此前 `importlib.metadata.version()` 是 1.4.1，
  与源码脱节；本轮 `uv pip install -e . --no-deps` 同步为 1.5.0。
  该目录被 gitignore，不入库。
- **并发干扰**：同期邻项目 `D:\qoder\vuln-agent` 有自己的测试批在跑，
  按 AGENTS.md 既有协议记账，未做跨项目停跑；本轮未见由它引起的红项。

---

## 6. 已知边界 / 未做

- Phase 382 的独立浏览器事实表测于 `edfe91d`，**不是 1.5.0 终树**；
  它只补「已投递 payload 是否真在浏览器执行」的事实，不给 TP/FP/F1，
  不冒充终树跑分、不进官方口径。
- 全量门禁有 2 个整文件零贡献的 skip；full 194 async 有 12 例
  sync-only SKIP。都如实列出，不宣称「所有用例都跑过」。
- 未跑：XSSMaze 1013 例全量、跨工具同台对照（需外部靶场与独立口径）、
  CI 的 `dependency-audit` / `windows-smoke` 远端 job。本轮是本机交付验收，
  远端 CI 由 push 触发，不在本报告的证据范围内。
- 未改：`#1 授权范围默认策略`仍待仓库归属者拍板（OPTIMIZATION §8）。

---

## 7. 证据路径

- 门禁日志（工作区外 scratch，仅本机留档）：
  `D:/qoder/_xssentinel_delivery_scratch/gate_quick_20261112.log`、
  `gate_batched_20261112.log`（A 对照）、`gate_batched_clean_20261112.log`（交付口径）、
  `gate_full_ranges_20261112.log`，逐文件日志与 timings 在其
  `xssentinel_batched_gate/<时间戳>/` 下。
- 靶场结果：`D:/qoder/_xssentinel_delivery_scratch/range{3,4,5,6}_delivery.json`。
- 制品：`D:/qoder/_xssentinel_delivery_scratch/dist2/xssentinel-1.5.0-py3-none-any.whl`。
- 仓库内：CHANGELOG [1.5.0]「验收(交付轮)」、AGENTS.md「当前状态(2026-11-12)」、
  `docs/OPTIMIZATION.md` §8.15、`benchmark/results/juice_render_20261110.{json,md}`。
