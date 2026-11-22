# Phase 407：async 无反射 L1 穷举收敛 —— 验收记录

**性质**：判定语义变更（降低无反射参数的 L1 候选预算）+ sync parity 保底补齐。事实表，非性能跑分。

## 改动（2 个产品文件）
- `core/async_scanner.py`：① 无反射时补 `ctx.find_prefix_encoded_marker` 重检（sync parity，零请求，修 XSSMaze encodingedge FN）；② 新增独立信号 `marker_absent`。
- `core/async_scanner_layers.py`：`_build_probe_candidates` 加 `marker_absent` 参数；无反射时 `cand_budget` 从 14 收敛到 3。

**关键设计（吸取一次失败教训）**：`marker_absent` 严格独立于 `marker_escaped`。后者是 async 的多阶段总开关（sandwich/generative、quote probe、transform cap 12→2、concat-stamp、尾部兜底）；第一次尝试把 absence OR 进 escaped 导致反射正例 pos-elem-01/neg-filter-01 变 FN（35→28 请求），已回滚并重做为"只砍候选预算、不碰总开关"。

## 根因
| case | 收敛前 async 请求 | 收敛后 | 检出来源 |
|---|---:|---:|---|
| neg-header-01（无反射负例） | 245 | 96 | TN（L7 专用层） |
| pos-xs-01（无反射正例） | 246 | 97 | xs_leak_surface (L7) |
| pos-cors-01 | 244 | 95 | cors_misconfig (L7) |
| pos-elem-01（反射正例） | 35 | 35 | reflected (L1) —— 不受影响 |
| neg-filter-01（绕过滤正例） | 145 | 145 | reflected (L1) —— 不受影响 |

sync 在 marker 无反射时 `return # not reflected -> skip`（scanner.py:778），async 缺此收口，fall-through 到完整 corpus ladder。收敛后无反射 case 请求腰斩，反射 case 零影响。

## 验收证据
1. **代表 case repro（解耦后）**：pos-elem-01 / neg-filter-01 / pos-attr-01（反射正例）保持 TP、请求不变；neg-header-01 / pos-xs-01 / pos-cors-01（无反射）请求腰斩、检出不变。
2. **分批 async 门**（`dev/_p407_batch_gate.py`，逐例落盘、无重试放大）：71/194 例完成（tree 3b2d105），剔除 1 个环境伪影后 **70 例干净 = 60 TP / 8 TN / 2 SKIP，零 FP、零 FN**；请求中位数 35，≥200 请求从收敛前的 51 例降为 **0 例**。
3. **sync 全量 194 门**：TP113/FP0/TN81/FN0、0 SKIP、F1=1.0000（Phase 407 只改 async 路径，sync 零影响，符合预期）。该轮性能 2961.7s 是本机 loopback 劣化（同树正常值 729.7s），非代码回归。
4. **守卫 + 变异**：`tests/test_phase407_marker_absent.py` **5 passed**（行为：absent→≤3 候选且 escaped 不被翻转；源码钉住 absence 不出现在任何 `not marker_escaped` 门控；prefix 保底零请求）；`dev/_p407_mutations.py` **3/3**（把 absence 折回 escaped / 连反射也收敛 / 删 prefix 保底，均 baseline 绿→mutated 红→字节还原绿）。

## 诚实边界
- **分批 async 门未跑满 194**：本机 loopback 严重劣化，原版 runner 的 `_evaluate_with_retries` 在 0 请求时反复 90s 重试，全量跑到 19 小时仍未完成被 kill；分批版（无重试）跑 71 例耗时 10159s（2.8 小时）后环境持续劣化停止。**未完成不冒充完成**。
- **唯一 FN（pos-dom-02）是环境伪影**：分批门里它 `scan_time=10003s`、`error="timeout after 90s"`、requests=97；当前代码单 case repro **x3 全部 TP**（4.4s / 96 请求）。按 Phase 69 规则带 error 的 vulnerable case 判 FN，但 error 是 loopback 超时，非判定回归。
- **性能不在本轮验收范围**：请求量下降的收益是"减少目标服务器压力/被封风险"，本机 loopback 劣化使墙钟数字不可比，不据此宣称速度提升。

## 复现
```
python dev/_p407_batch_gate.py --engine async --port <clean> --tree <sha>   # 分批全量（可续跑）
python benchmark/repro_case.py <case_id> <port> async                        # 单 case
python -m pytest tests/test_phase407_marker_absent.py -q
```
