# 终树全量门禁证据（2026-11-09 晚，本机实测）

树：`00a017d`（Phase 378 后，工作区干净）。这一轮补跑 Phase 372–378 三轮
`[Unreleased]` 增量欠下的验收债。所有数字来自本轮自己的运行，判词与产物
路径一并给出；引用时**必须带跳过数**。

## 1. full 194 strict gate 双引擎 —— 各 exit 0

命令（报告重定向到工作区外，`dev/gate_run_scratch.py`）：

```bash
.venv/Scripts/python.exe dev/gate_run_scratch.py --strict-gate --engine sync  --port 18941
.venv/Scripts/python.exe dev/gate_run_scratch.py --strict-gate --engine async --port 18942
```

| 引擎 | 时间段 | 判词 | 跳过 | 产物 |
|---|---|---|---|---|
| sync | 20:14:37–20:20:21（344s） | `FP0 FN0 ERROR0 over 194 scored cases` | **0 SKIP** | `%TEMP%/xssentinel_gate/benchmark_20261109_202021.json` |
| async | 20:20:21–20:26:04（343s） | `FP0 FN0 ERROR0 over 182 scored cases` | **12 SKIP** | `%TEMP%/xssentinel_gate/benchmark_20261109_202604.json` |

async 的 12 SKIP 与 11-08 记录的 manifest 声明 sync-only 口径一致。
quick 64 双引擎已于同日早些时候补跑（sync 64 scored / 0 SKIP、
async 63 scored / 1 SKIP，各 exit 0、FP0/FN0/ERROR0，端口 18931/18932）。
⇒ **四档 strict gate 在 11-09 全部由本树跑过。**

## 2. 全量分批回归门禁 —— exit 0

```bash
# 关键：关掉 pytest 的旧 numbered tmp 目录清理，原因见 §3
export PYTEST_ADDOPTS='-o tmp_path_retention_policy=all -o tmp_path_retention_count=10000'
.venv/Scripts/python.exe dev/batched_gate_scratch.py --jobs 4 --quiet
```

20:49:01–20:56:40（**459s**）：

```
297/297 files green in 459s; failures: none
skipped tests: 13 across 6 file(s)
  test_dom_engine_probe_urls.py: 4
  test_oracle_default_sent.py: 3          (WHOLE FILE -- contributed nothing)
  test_parity_full_matrix.py: 1
  test_passive_mitm.py: 1
  test_phase209_accept_encoding.py: 1
  test_stored_e2e_acceptance.py: 3       (WHOLE FILE -- contributed nothing)
```

**297/297 绿 + skip 13 例 / 6 文件 + 2 个整文件零贡献**，三者一起引用。
逐文件耗时：`%TEMP%/xssentinel_batched_gate/20261109-204901/_timings.txt`；
最慢 `test_dom_sink_matrix.py` 178.9s，前 15 个合计 810s（wall 459s，`--jobs 4`）。

## 3. 前两轮失败不是回归：完整归因（A/B 对照）

前两次运行都是红的，**没有一次是产品测试失败**：

| run | 时间 | 结果 | 失败文件数 |
|---|---|---|---|
| R1 | 20:26:04–20:34:42（517s） | 265/297 绿 | 32 |
| R2 | 20:38:29–20:47:20（531s） | 261/297 绿 | 36 |
| R3（修法后） | 20:49:01–20:56:40（459s） | **297/297 绿** | 0 |

证据链：

1. R1 的 35 个保留日志中 **35/35 含 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`**，
   **0 个含 `FAILED` / `ERROR` / `N failed`**。每个失败文件的 stdout 都是
   `........ [100%]`（测试全绿），只有 stderr 有守卫消息，随后 rc 被改成 1。
   `run_all_batched.py` 按 rc 判红，所以这 32 个红是环境形态，不是回归。
2. 第一次假设是「自定义 TEMP 把 pytest tmp 拉进监控区」，做 A/B：R1 的三个
   失败文件（`test_report` / `test_llm_pool` / `test_temp_dir_fallback`）在
   系统默认 TEMP 下单跑 **121 passed**。但 R2 换回系统 TEMP 全量重跑
   **仍 36 红** ⇒ 假设被否证。
3. R2 日志里的 targets 给出了真因：
   `D:\qoder\xssentinel\tests\_pytest_tmp\pytest-of-Administrator\garbage-*`
   —— **删除发生在工作区内**。项目把 pytest tmp 根钉在 `tests/_pytest_tmp`，
   297 个 pytest 子进程共享它，每个 session 按 retention 策略清理旧的
   numbered 目录；累计超过 safe-delete 的 50 次/turn 阈值后，后续删除被拒，
   rc=1。改 TEMP 无效，因为删的根本不是 TEMP 下的路径。
4. 修法不改任何产品/测试代码：用环境变量把 pytest 的保留数调大，
   让并发 session 不再互相清理。补一次 A/B（2 个文件）**68 passed**，
   且工作区内新增 `garbage-*` 为 0；随后 R3 全量 297/297 绿。

⇒ **结论**：判定面零改动的前提下，四档 strict gate 与全量分批门在终树上
全部通过；R1/R2 的红 100% 由本机 safe-delete 守卫造成，已用 A/B + 日志
普查定性，不当绿也不当回归。

## 4. 复现要点（本机环境）

- 精度门报告与分批门日志都要落在工作区外：
  `dev/gate_run_scratch.py`（已有）、`dev/batched_gate_scratch.py`（本轮新增，
  把 `tests/run_all_batched.py` 的 `LOG_DIR` 在进程内重绑定到 `%TEMP%`）。
- 全量分批门必须带 `PYTEST_ADDOPTS` 的 retention 覆盖，否则工作区内
  `tests/_pytest_tmp` 的清理会撞 50 次/turn 守卫。
- 端口用 189xx（避开 Windows 保留段 8810–9109）；跑前固定
  `NO_PROXY=127.0.0.1,localhost` 与 `no_proxy` 小写形式。
- 引用任何门禁结果必须同时给出跳过数；整文件 skip 的文件什么都不曾贡献。
