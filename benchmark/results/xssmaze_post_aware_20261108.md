# XSSMaze POST-aware 跑分口径（2026-11-08）

> **这是测量口径修复，不是检测能力提升。**
> 只改 `dev/_xssmaze/wrapper.py`（测试驱动器）；**产品代码、官方 GT、
> runner 记分逻辑一律未动**。新口径以 opt-in 方式提供，默认 wrapper
> 逐字节不变，旧 scorecard 仍可复现。
> **本轮数字不得与上一轮 F1 0.981 直接比较**，也不能当作产品能力提升引用。

## 一、问题：POST-only 端点从来没被真正测过

官方 runner `dev/_xssmaze/benchmark.py::get_full_url()` 只把 **URL** 传给
`--custom-scanner`，`/map/json` 里的 `method` / `params` / `vuln.delivery`
全部丢失。wrapper 于是用默认 GET、无 body 去扫 POST-only 端点 —— 参数
根本到不了靶场。

这解释了 2026-11-08 全量 scorecard 里 `postmethod 0/6`、`post 0/2`：
**是测量盲区，不是"扫描器找不到 POST XSS"的证据**。

数据契约实测（`/map/json`）：1064 个唯一 path、28 个 POST、5 个 QUERY、
**0 个同 path 方法冲突**，所有 POST 端点都有 `params`。

## 二、修法：opt-in + 单一命令构造器

`dev/_xssmaze/wrapper.py`：

- `XSSMAZE_POST_AWARE=1` **且** `XSSMAZE_MAP_INDEX=<json>` 时，按 URL path
  查索引；`method == POST` 才追加 `-m POST -d <urlencoded params>`。
- 索引来自官方 `/map/json` 的 `{path: {method, params}}`，只落在 TEMP。
- **fail-safe**：开关关 / 索引缺失 / 路径不存在 / 解析失败 / GET 端点，
  一律返回 `None`，命令与历史 wrapper **逐位一致**。
- `_build_cmd()` 是唯一命令构造点；invlog 的 err 列追加 `POST:<params>`
  作为逐例审计标记。

新增 `tests/test_xssmaze_post_aware_wrapper.py`（7 例）：自建 POST-only 与
GET-only 本地靶，用**真实 wrapper 子进程**验证；另用 AST 源码断言钉住
opt-in 开关与单一构造器。

## 三、证据链

| 环节 | 结果 |
|---|---|
| 红测（修前） | **2 failed**：POST-only 端点全程只收到 GET；源码无 opt-in 开关。3 个反向对照修前即绿 |
| 修后 | **7 passed** |
| 变异对照 ① | 把 opt-in 改成 always-on ⇒ 红 2 例（含"默认不变"）→ restored 绿 |
| 变异对照 ② | 禁用 POST body 分支 ⇒ 红 2 例（含"POST 检出"）→ restored 绿；两轮均字节级还原 ⇒ **PASS** |
| 回归 | `test_xssmaze_post_aware_wrapper` + `test_xssmaze_scoring` **15 passed** |
| ruff | 全仓 `All checks passed` |

**过程中 ruff 抓到一个真 bug**：大块替换时误删了 `_counts()`，测试因未设
`XSSMAZE_INVLOG` 没走到那行。已补回，并新增 `test_invlog_records_the_post_shape`
锁住该路径 —— 这是"测试没覆盖的分支"的现场例子。

## 四、真实 XSSMaze 小样本 A/B

8 个 POST 端点 + 8 个 GET 端点，同一 wrapper、仅切开关：

- POST：**6/8 从「0 finding」变为「1 finding」**；
  `post/level2`、`postmethod/level3` 仍漏 —— **真 FN，不是口径问题**。
- GET：**8/8 findings 逐位不变**（1/4/8/5/4/4/1/1）。

⇒ 口径修复只作用于 POST 种群，旧口径的 GET 结果没有被污染。

## 五、官方 1013 例全量（POST-aware 口径）

| 口径 | TP | FN | FP | Precision | Recall | F1 | 时间 |
|---|---|---|---|---|---|---|---|
| 旧（GET-only，同日 1959.1s） | 975 | 38 | 0 | 100.0% | 96.2% | 0.981 | 1959.1s |
| **新（POST-aware）** | **987** | **26** | **0** | **100.0%** | **97.4%** | **0.987** | **2039.6s** |

controls 27 上零误报；1037 次调用 0 个非 0 rc；**28 个 POST 端点全部
带 `POST:` 标记**，与索引一一对应。

### 逐例差集归因（不拿总数字糊过去）

- **GAIN 14**：`headless-generator` level1/2/3/4/6（5）、
  `postmethod` level1/2/4/5/6（5）、`post-level1`、`multipart-level1`、
  `realworld_input-level3`、`domsink-level7`。
- **LOSS 2**：`dom-level6`、`domsink-level3`。**两者索引里都是 GET**，
  且新 invlog 里**完全没有这两个 URL 的任何一行** —— wrapper 进程没走到
  写日志那步，被 runner 的 90s 超时杀掉。单跑复现：两个端点在 legacy 与
  POST-aware 下**都稳定 1 finding / rc=0** ⇒ **环境性超时伪影，不是判定
  变化，也不是 POST-aware 的副作用**。新 invlog 1037 行 vs 旧 1039 行，
  正好差这些未完成调用（`/dom/level9/` 也缺失，但两轮都未检出，不影响分数）。
- 净 +12 与 TP 差一致。**没有自行"修正"官方判词**：987/26/0 就是
  runner 的原始输出，不额外折算"若剔除超时应是多少"。

运行参数与上一轮**除开关外完全相同**：`--reach server`、`{URL}` per-URL
wrapper、`--detect-json findings[].url`、`XSSMAZE_TIMEOUT=110`、
`--scanner-timeout 90`。产物
`benchmark/results/xssmaze_full_post_aware_20261108.{json,md}`，
逐例日志 TEMP `xmz_full_post_invlog_20261108.tsv`。

## 六、如何正确引用这两个数字

- **旧口径（GET-only, F1 0.981）**：与历史基线同口径，用于纵向对比、
  README / CHANGELOG 引用。
- **新口径（POST-aware）**：回答"给足请求形状后能检出多少"，单独标注，
  **不得**写成"产品能力提升 +N"。
- 差值主要来自"POST 端点终于拿到了 body"，不是判定逻辑变化。
  要证明能力提升，得在**同一口径**下对跑或修真 FN。

## 七、仍未处理

- 2 个真实 FN：`post/level2`、`postmethod/level3`（小样本实测）。
- WIP 既有红项（非本轮引入）：`test_architecture_scale`
  `scanner.py 2793 > 2650`、`test_doc_gate_parity` CHANGELOG 1.4.3 vs
  `__version__` 1.4.4。
- `QUERY` 方法端点（5 个）本轮未特殊处理。
- 未提交 commit。
