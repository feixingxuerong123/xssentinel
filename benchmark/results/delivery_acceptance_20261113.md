# XSSentinel 交付验收报告 · 2026-11-13

- tree: 交付终树(Phase 387–389 全部落地 + 2.1.0 定版文档);与本发布提交的
  唯一差异是 CHANGELOG `[2.1.0]`「验收(交付轮)」的数字文本。
- version: **2.1.0**(`__version__` / dist 元数据 / CLI `-V` / CHANGELOG
  四处同源)
- 口径:重活串行(精度门与套件不并行);`env -u PYTHONPATH` 干净环境;
  `TEMP`/`TMP` 指向工作区外可写 scratch;全量分批门加 `PYTEST_ADDOPTS`
  关闭 pytest tmp 自动清理;绿一律连 skip 数一起报;零永远不是通过。
  **全部数字来自本轮在这棵终树上的自跑**,不引用 11-13 早间 / 前几轮
  WIP 树上的数字。

---

## 1. 交付边界:本版落地了什么

| 类别 | 内容 |
|---|---|
| 定级 | `[Unreleased]` 收成 `[2.1.0] - 2026-11-13`(按「新增能力走 minor」:strict gate 新增墙钟预算维度),保留空 `[Unreleased]` 段;`__version__` 2.0.1 → 2.1.0 |
| Phase 387 | 四档实测墙钟基线 + 推导 ceiling + 未测量组合一律 `UNBUDGETED`;守卫 11 例、变异 7/7、源码断言钉住调用点 |
| Phase 388 | 推翻 2.0.1 的「fn_net 2 个真 FP / L7 降档」:72 臂确定性矩阵证明 8/9 形状是真阳性;裁定工具与勘误固化「候选 ≠ 判定」 |
| Phase 389 | 把唯一 verifier-only 的 `marquee/onstart` 在沙箱事实表标 `inert`,让既有 veto 收回确认;元素 × 属性 pair、语料集合不动;同量具重测 `verifier_only` 1→0 |
| 文档 | AGENTS 当前状态、CHANGELOG 2.1.0 章节与验收节、OPTIMIZATION §8.18–8.20 |
| 未改 | CLI 参数契约、legacy MCP 帧、REST `/api/v1/scans`、CI 配置、历史跑分数字 |
| 勘误 | 2.0.1 / §8.17 关于「2 个真 FP / L7 降档」的带日期原文**保留不改**,以 388 勘误为准(守卫同时钉住勘误存在与原文仍在) |

无破坏性变更。版本同源守卫
`test_doc_gate_parity.py::test_changelog_latest_version_matches_package_version`
绿(19 例文档/切片守卫全绿)。

## 2. 门禁结果(终树自跑,绿一律连 skip 数一起报)

> 本表与 CHANGELOG `[2.1.0]`「验收(交付轮)」逐字同源;若两处不一致,
> 以 CHANGELOG 为准。

| 门禁 | 结果 | skip |
|---|---|---|
| ruff 全仓 E/F/W | `All checks passed` | — |
| 文档 / 切片 / 版本守卫 | **19 passed / 0 failed** | **0** |
| 新守卫 387/388/389 | **24 passed / 0 failed** | **0** |
| 沙箱保真度 + gate | **20 passed / 0 failed** | **0** |
| 邻接组(18 文件) | **265 passed / 0 failed**,40.85s | **0** |
| 全量分批门 `--jobs 4` | **308/308 文件绿**,1666s,failures none | **66 例 / 13 文件**(2 整文件零贡献) |
| quick 64 `--strict-gate` sync | **175.9s vs ceiling 330s → PASSED**;FP0 FN0 ERROR0,64 scored | **0** |
| quick 64 `--strict-gate` async | **180.8s vs ceiling 350s → PASSED**;63 scored | **1** |
| full 194 `--strict-gate` sync | **405.5s vs ceiling 795s → PASSED**;194 scored | **0** |
| full 194 `--strict-gate` async(首跑) | 574.7s;质量门 **FN=1: pos-dom-03**(环境,见下) | 12 |
| full 194 `--strict-gate` async(重跑) | **616.8s vs ceiling 840s → PASSED**;FP0 FN0 ERROR0,182 scored | **12** |

**红项归因(A/B)**:full/async 首跑的 `pos-dom-03` 是 **loopback 噪声,
非本版回归**。① 同树单点复测 **5/5 TP**(3.86–4.33s,requests=28,
finding=1);② 首跑该用例 25.5s 无 finding、日志 2 次
`WinError 10054`、同轮分批门 1666s(历史 501s);③ 判定面源码自 389 提交
`943c674` 起逐字节未变(`git diff` 只有 `__init__.py` 版本字符串);
④ 同树重跑 FP0/FN0/ERROR0。首跑不当绿记,两轮数字都保留。

## 3. 打包冒烟

`uv build --wheel` 在**工作区外副本树**上构建(工作区内构建会反复覆盖
`build/`,触发本机 safe-delete 守卫的 50 次上限;这是宿主限制,不是产品
缺陷):

- wheel:`xssentinel-2.1.0-py3-none-any.whl`,1,054,158 B;
- `xssentinel/data/` **仅 8 个语料文件**;`llm_state.json` 与
  `llm_providers.json` **均不在包内**(打包卫生守卫与真实 wheel 双向确认);
- 解压后在**工作区外** cwd 运行:`import xssentinel` 的 `__file__` 指向
  wheeltest、版本 `2.1.0`;`python -m xssentinel -V` 输出
  `xssentinel 2.1.0`。

## 4. 如实记账与开放项

- 全量分批 pytest 门本轮**补跑**(387/388/389 三轮均记为未跑,不拿历史
  数字顶账)。
- parity 全矩阵 opt-in 门 **2/194 存量分歧**仍开放(A/B 定谳非本版引入,
  官方 strict 口径四档全绿不受影响)。
- `<div onstart>` 等非 marquee 元素上的 `onstart` 本版**没量过**,按
  「没量过不进门禁」保持原状,列为后续测量项。
- PyPI Trusted Publisher 仍是归属者的**外部待办**(GitHub 仓库设置,
  本机无法代配)。

## 5. 证据索引

- 决策过程: `docs/OPTIMIZATION.md` §8.18 / §8.19 / §8.20
- 轮次报告: `phase387_perf_budget_20261113.md`、
  `phase388_fp_candidate_adjudication_20261113.md`、
  `phase389_marquee_inert_20261113.md`
- 事实表: `perf_baseline_*_20261113.json`(四档基线)、
  `phase388_primitive_matrix_20261113.json`(修复前)、
  `phase389_primitive_matrix_20261113.json`(修复后)
- 逐档门禁日志: `benchmark/results/_local_archive/phase390_gate_*.log`、
  `phase390_batched.log`
