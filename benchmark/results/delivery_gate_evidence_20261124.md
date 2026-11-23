# 2.2.1 交付门禁证据（2026-11-23~24，终树 `2982314`）

事实表，非跑分。所有数字为本轮在交付终树上的自跑，引用带跳过数。
产品代码自 `2982314` 起冻结；门禁期间只改文档与本证据文件。

## 短守卫批

13 文件 **142 passed / 0 skipped**（16.4s）：
`test_phase400_headless_auth_cookies` / `test_phase404_competitor_corpus` /
`test_phase405_onload_scheme` / `test_phase407_marker_absent` /
`test_competitor_runner` / `test_llm_propose` / `test_phase365_mcp_url_parity` /
`test_async_headless_verify` / `test_phase217_sync_headless_verify` /
`test_doc_gate_parity` / `test_architecture_scale` /
`test_package_data_hygiene` / `test_quick_gate_slice`。
ruff 全仓 `All checks passed!`；`import xssentinel` OK，`__version__` 2.2.1。

## 四档 strict gate

| 档 | 引擎 | TP/FP/TN/FN | ERROR | SKIP | 性能 | 报告 |
|---|---|---|---|---|---|---|
| full 194 | sync | 113/0/81/0 | 0 | 0 | PASSED 365.6s/795s | `delivery_full_sync_20261124.json` |
| quick 64 | sync | 36/0/28/0 | 0 | 0 | PASSED 267.5s/330s | `delivery_quick_sync_20261124.json` |
| quick 64 | async | 36/0/27/0 | 0 | 1 | PASSED 142.7s/350s | `delivery_quick_async_20261124.json` |
| full 194 | async（分批门） | 106/0/74/0（192 scored） | 2* | 12 | 见下 | `delivery_async_full_20261123.json` |

\* full async 用无重试分批门 `dev/_p407_batch_gate.py`（逐例落盘、可续跑、
90s 封顶）。2 个带 error 的 case（`neg-csp-05` ERROR / `pos-worker-01` FN）
单 case repro 全干净（TN/TP，6.2s，`delivery_async_repro_20261123.json`）⇒
环境超时伪影非回归。计入 repro 后等效 **TP107/FP0/TN75/FN0、12 SKIP**，与
历史 full async（107/0/75/0）逐位一致。12 SKIP 为 manifest 声明 sync-only
的 stored 用例 async 臂。

## async 全量官方性能判词：本轮未取得（如实记）

- 官方 runner（`gate_run_scratch.py --strict-gate --engine async`）在本机
  loopback 波动下重试放大挂起 ~2h（00:56→02:59，无判词无报告），按 Phase 407
  方法论终止、**不采用**。
- clean 分批复跑至 55 例再劣化（`pos-script-04/06` 90s 超时伪影）亦终止，
  **不采用**。
- async 性能口径以 quick async PASSED（142.7s/350s）+ Phase 405 full async
  边界（860.9s/840s，超 2.5%，请求量 2.6× 本机吞吐边界）+ Phase 407 无反射
  请求腰斩为准。**不冒充 full async 性能 PASSED**；待 loopback 稳定期补跑。

## 环境事件（不改产品/测试代码）

1. Windows TCP 排除段会话中漂移到 **18932–19131**，19093 bind 撞
   WinError 10013 ⇒ 门禁改用 18931 / 20504 / 20506（bind 前逐口探针）。
2. loopback 阵发劣化（连接 000/2s、case 90s 超时）：quick sync 首轮性能
   FAILED 3803.5s/330s 即此形态，健康期复跑 267.5s PASSED；full async 首轮
   分批 elapsed 29850s 亦为劣化期墙钟，**不可比、不宣称提速**。
3. 分批门聚合文件放系统临时目录（`C:/Users/Administrator/.cache/xssentinel/tmp`）
   避开 safe-delete 50 次/turn 配额，终稿一次性拷入 `benchmark/results/`。

## 凭据处置

`.gitignore` 挡 `benchmark/results/llm_state.json`（运行期状态）与
`llm_local_glm53_20261119.json`（含真实 API key）；16 份 DVWA AI 报告 key
为产品脱敏形式 `sk-369***f3cb`，脚本/交接文档逐一 grep 确认无完整密钥/
PHPSESSID 后入库。详见 OPTIMIZATION §8.39。